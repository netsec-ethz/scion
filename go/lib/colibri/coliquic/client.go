// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coliquic

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/topology"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

type GRPCClientDialer interface {
	libgrpc.Dialer
}

// ServiceClientOperator can obtain COLIBRI gRPC clients to talk to the service.
// The goal of this construction is to avoid dialing more than once to the same destination,
// if we have dialed to it before. We would have to:
// - Ensure the QUIC ID on the channel is different for different channels.
// - Ensure the QUIC ID on the channel is the same for the same channel.
// - Ensure we return a gRPC client using the correct path (the path is used at the server to
//   measure the BW used by the services).
type ServiceClientOperator struct {
	connDialer       GRPCClientDialer
	neighbors        map[uint16]*snet.UDPAddr // SvcCOL addr per interface ID
	neighborsMutex   sync.Mutex
	srvResolver      ColSrvResolver
	colServices      map[addr.IA]*snet.UDPAddr // cached discovered addresses
	colServicesMutex sync.Mutex
}

func NewServiceClientOperator(topo *topology.Loader, router snet.Router,
	clientConn GRPCClientDialer) (*ServiceClientOperator, error) {

	operator := &ServiceClientOperator{
		connDialer: clientConn,
		neighbors:  make(map[uint16]*snet.UDPAddr, len(topo.InterfaceIDs())),
		srvResolver: &DiscoveryColSrvRes{
			Router: router,
			Dialer: clientConn,
		},
		colServices: make(map[addr.IA]*snet.UDPAddr),
	}
	operator.initialize(topo)

	return operator, nil
}

func (o *ServiceClientOperator) DialSvcCOL(ctx context.Context, dst *addr.IA) (
	colpb.ColibriServiceClient, error) {

	o.colServicesMutex.Lock()
	defer o.colServicesMutex.Unlock()

	addr, ok := o.colServices[*dst]
	if !ok {
		var err error
		addr, err = o.srvResolver.ResolveColibriService(ctx, dst)
		if err != nil {
			return nil, err
		}
		o.colServices[*dst] = addr
	}

	conn, err := o.connDialer.Dial(ctx, addr)
	if err != nil {
		log.Debug("error dialing a grpc connection", "addr", addr, "err", err)
		return nil, err
	}
	return colpb.NewColibriServiceClient(conn), nil
}

// ColibriClient finds or creates a ColibriClient that can reach the next neighbor in
// the path passed as argument. The underneath connection will be COLIBRI or regular SCION,
// depending on the type of the path passed as argument.
func (o *ServiceClientOperator) ColibriClient(ctx context.Context, transp *base.TransparentPath) (
	colpb.ColibriServiceClient, error) {

	egressID := transp.Steps[transp.CurrentStep].Egress
	rAddr, ok := o.neighborAddr(egressID)
	if !ok {
		return nil, serrors.New("client operator not yet initialized for this egress ID",
			"egress_id", egressID, "neighbor_count", len(o.neighbors))
	}
	rAddr = rAddr.Copy() // preserve the original data

	buf := make([]byte, transp.RawPath.Len())
	transp.RawPath.SerializeTo(buf)

	// prepare remote address with the new path
	switch transp.RawPath.Type() {
	case scion.PathType: // don't touch the service path
		rAddr.Path = snetpath.SCION{Raw: buf}
	case colibri.PathType:
		rAddr.Path = snetpath.Colibri{Raw: buf}
	default:
		// Do nothing when e.g. empty path for E2EReservations
		// E2EReservations must eventually travel through colibri path
		// In that case they will follow same logic as above
	}

	conn, err := o.connDialer.Dial(ctx, rAddr)
	if err != nil {
		log.Debug("error dialing a grpc connection", "addr", rAddr, "err", err)
		return nil, err
	}
	return colpb.NewColibriServiceClient(conn), nil
}

func (o *ServiceClientOperator) neighborAddr(egressID uint16) (*snet.UDPAddr, bool) {
	o.neighborsMutex.Lock()
	defer o.neighborsMutex.Unlock()

	addr, ok := o.neighbors[egressID]
	return addr, ok
}

// initialize waits in the background until this operator can obtain paths to all the remaining IAs.
func (o *ServiceClientOperator) initialize(topo *topology.Loader) {

	remainingIAs := neighbors(topo)
	go func() {
		defer log.HandlePanic()
		log.Info("will initialize colibri client operator", "neighbor_count", len(remainingIAs))

		for len(remainingIAs) > 0 {
			time.Sleep(2 * time.Second)
			log.Debug("colibri client operator initializing", "remaining", len(remainingIAs))
			newNeighbors := make(map[uint16]*snet.UDPAddr)
			remainingIAs = o.findNeighbors(newNeighbors, remainingIAs)
			if len(newNeighbors) > 0 {
				o.neighborsMutex.Lock()
				for egressID, addr := range newNeighbors {
					o.neighbors[egressID] = addr
				}
				o.neighborsMutex.Unlock()
			}
		}
		log.Info("colibri client operator initialization complete")
		go func() {
			defer log.HandlePanic()
			o.periodicResolveNeighbors(topo)
		}()
		go func() {
			defer log.HandlePanic()
			o.periodicDiscoverServices()
		}()
	}()
}

// periodicResolveNeighbors periodically scans the topology and gets new paths for the neighbors.
func (o *ServiceClientOperator) periodicResolveNeighbors(topo *topology.Loader) {
	for {
		time.Sleep(15 * time.Minute)
		neighbors := neighbors(topo)
		log.Debug("colibri client operator periodically findind neighbors",
			"count", len(neighbors))
		newAddrBook := make(map[uint16]*snet.UDPAddr)
		remainingIAs := make(map[uint16]addr.IA)
		for id, ia := range neighbors {
			remainingIAs[id] = ia
		}
		for iter := 0; len(remainingIAs) > 0 && iter < 30; iter++ {
			time.Sleep(2 * time.Second)
			remainingIAs = o.findNeighbors(newAddrBook, neighbors)
			log.Debug("periodic resolve neighbors",
				"total", len(neighbors), "missing", len(remainingIAs))
		}
		if len(remainingIAs) > 0 {
			// oops, we couldn't deal with all neighbors. Do not touch the existing addressbook
			missing := make([]string, 0, len(remainingIAs))
			for id, ia := range remainingIAs {
				missing = append(missing, fmt.Sprintf("%s on ifid %d", ia, id))
			}
			log.Error("periodic resolve neighbors: neighbors without address",
				"missing_count", len(remainingIAs), "total", len(neighbors),
				"missing", strings.Join(missing, ","))
		} else {
			o.neighborsMutex.Lock()
			o.neighbors = newAddrBook
			o.neighborsMutex.Unlock()
		}
	}
}

func (o *ServiceClientOperator) periodicDiscoverServices() {
	for {
		time.Sleep(15 * time.Minute)
		// get all existing destinations and re-query them
		o.colServicesMutex.Lock()
		ias := make([]addr.IA, 0, len(o.colServices))
		for ia := range o.colServices {
			ias = append(ias, ia)
		}
		// re-querying could take some time, free the lock
		o.colServicesMutex.Unlock()
		addrBook := make(map[addr.IA]*snet.UDPAddr)
		failed := 0
		for _, ia := range ias {
			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
			addr, err := o.srvResolver.ResolveColibriService(ctx, &ia)
			cancelF()
			if err == nil {
				addrBook[ia] = addr
			} else {
				failed++
			}
		}
		log.Debug("periodic discover colibri services", "failed", failed, "found", len(addrBook))
		// quickly set the new address book
		o.colServicesMutex.Lock()
		o.colServices = addrBook
		o.colServicesMutex.Unlock()
	}
}

// neighbors returns the neighboring IAs by egress interface ID.
func neighbors(topo *topology.Loader) map[uint16]addr.IA {
	neighbors := make(map[uint16]addr.IA)
	for ifid, info := range topo.InterfaceInfoMap() {
		neighbors[uint16(ifid)] = info.IA
	}
	return neighbors
}

// findNeighbors sets the address of the neighbors in the addrBook parameter.
// Returns the neighbors for which it could not find an address.
func (o *ServiceClientOperator) findNeighbors(addrBook map[uint16]*snet.UDPAddr,
	neighbors map[uint16]addr.IA) map[uint16]addr.IA {

	missingNeighbors := make(map[uint16]addr.IA)
	for egress, ia := range neighbors {
		colAddr, err := o.resolveAddr(&ia)
		if err != nil {
			log.Debug("error resolving address for colibri service", "err", err)
			missingNeighbors[egress] = ia
			continue
		}
		addrBook[egress] = colAddr
	}
	return missingNeighbors
}

func (o *ServiceClientOperator) resolveAddr(ia *addr.IA) (*snet.UDPAddr, error) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCtx()
	return o.srvResolver.ResolveColibriService(ctx, ia)
}

type ColSrvResolver interface {
	ResolveColibriService(ctx context.Context, ia *addr.IA) (*snet.UDPAddr, error)
}

type DiscoveryColSrvRes struct {
	Router snet.Router
	Dialer libgrpc.Dialer
}

func (r *DiscoveryColSrvRes) ResolveColibriService(ctx context.Context, ia *addr.IA) (
	*snet.UDPAddr, error) {

	path, err := r.Router.Route(context.Background(), *ia)
	if err != nil || path == nil {
		return nil, serrors.New("no route to IA", "ia", ia, "err", err, "path", path)
	}

	ds := &snet.SVCAddr{
		IA:      *ia,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcDS,
	}
	conn, err := r.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.ColibriServices(ctx, &dpb.ColibriServicesRequest{}, libgrpc.RetryProfile...)
	if err != nil {
		return nil, serrors.WrapStr("discovering colibri services", err)
	}
	if len(rep.Address) == 0 {
		return nil, serrors.New("no colibri services discovered", "ia", ia.String())
	}

	host, err := net.ResolveUDPAddr("udp", rep.Address[0])
	if err != nil {
		return nil, serrors.WrapStr("parsing udp address for colibri service", err,
			"udp", rep.Address[0])
	}

	return &snet.UDPAddr{ // TODO(juagargi) should be a SVCAddr instead
		IA:      *ia,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		Host:    host,
	}, nil
}
