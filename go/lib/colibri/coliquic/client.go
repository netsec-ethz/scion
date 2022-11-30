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

	"github.com/scionproto/scion/go/lib/addr"
	libcol "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/infraenv"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

type TopoLoader interface {
	InterfaceIDs() []uint16
	InterfaceInfoMap() map[common.IFIDType]topology.IFInfo
	IA() addr.IA
}

// ServiceClientOperator can obtain COLIBRI gRPC clients to talk to the service.
// The goal of this construction is to avoid dialing more than once to the same destination,
// if we have dialed to it before. We would have to:
// - Ensure the QUIC ID on the channel is different for different channels.
// - Ensure the QUIC ID on the channel is the same for the same channel.
// - Ensure we return a gRPC client using the correct path (the path is used at the server to
//   measure the BW used by the services).
type ServiceClientOperator struct {
	initialized          bool
	gRPCDialer           grpc.Dialer
	neighboringColSvcs   map[uint16]*snet.UDPAddr // SvcCOL addr per egress interface ID
	neighboringColSvcsMu sync.Mutex
	neighboringIAs       map[uint16]addr.IA
	srvResolver          ColSrvResolver
	colServices          map[addr.IA]*snet.UDPAddr // cached discovered addresses
	colServicesMutex     sync.Mutex
}

func NewServiceClientOperator(topo TopoLoader, pconn net.PacketConn, router snet.Router,
	resolver messenger.Resolver) (*ServiceClientOperator, error) {

	tlsConfig, err := infraenv.GenerateTLSConfig()
	if err != nil {
		return nil, err
	}
	connDialer := NewPersistentQUIC(pconn, tlsConfig, nil)
	gRPCDialer := &grpc.QUICDialer{
		Dialer: connDialer,
		Rewriter: &messenger.AddressRewriter{
			// We never resolve addresses in the local AS, so pass a nil here.
			SVCRouter:             nil,
			Router:                router,
			Resolver:              resolver,
			SVCResolutionFraction: 1.337,
		},
	}

	operator := &ServiceClientOperator{
		gRPCDialer:         gRPCDialer, // persistent dialer
		neighboringColSvcs: make(map[uint16]*snet.UDPAddr, len(topo.InterfaceIDs())),
		srvResolver: &DiscoveryColSrvRes{
			Router:     router,
			GRPCDialer: gRPCDialer, // persistent dialer
		},
		colServices: make(map[addr.IA]*snet.UDPAddr),
	}
	operator.initialize(topo)

	return operator, nil
}

// Neighbors returns a map of the neighboring IAs, keyed by interface ID connecting to them.
func (o *ServiceClientOperator) Neighbor(interfaceID uint16) addr.IA {
	return o.neighboringIAs[interfaceID]
}

func (o *ServiceClientOperator) Initialized() bool {
	o.neighboringColSvcsMu.Lock()
	defer o.neighboringColSvcsMu.Unlock()
	return o.initialized
}

func (o *ServiceClientOperator) ColibriClientForIA(ctx context.Context, dst *addr.IA,
) (colpb.ColibriServiceClient, error) {

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
	return o.colibriClient(ctx, addr)
}

// deleteme:
// the client seems not to be working correctly (it dials to a wrong destination??)

// ColibriClient finds or creates a ColibriClient that can reach the next neighbor in
// the path passed as argument. The underneath connection will be COLIBRI or regular SCION,
// depending on the type of the path passed as argument.
func (o *ServiceClientOperator) ColibriClient(
	ctx context.Context,
	egressID uint16,
	transport *colpath.ColibriPathMinimal,
) (colpb.ColibriServiceClient, error) {

	rAddr, err := o.neighborAddrWithTransport(egressID, transport)
	if err != nil {
		return nil, err
	}
	return o.colibriClient(ctx, rAddr)
}

func (o *ServiceClientOperator) DebugClient(
	ctx context.Context,
	egressID uint16,
	colAddr *colpath.ColibriPathMinimal,
) (colpb.ColibriDebugServiceClient, error) {

	rAddr, err := o.neighborAddrWithTransport(egressID, colAddr)
	if err != nil {
		return nil, err
	}
	return o.debugClient(ctx, rAddr)
}

// deleteme replace neighborAddrWithTransport with calls to this function:
func (o *ServiceClientOperator) neighborAddrWithTransport(
	egressID uint16,
	transport *colpath.ColibriPathMinimal,
) (*snet.UDPAddr, error) {

	rAddr, ok := o.neighborAddr(egressID)
	if !ok {
		return nil, serrors.New("client operator not yet initialized for this egress ID",
			"egress_id", egressID, "neighbor_count", len(o.neighboringColSvcs))
	}
	rAddr = rAddr.Copy() // preserve the original data

	// deleteme try to send using directly the transport IA and Host fields
	// if transport is nil, just use a path obtained here (above thru neighborAddr)
	switch {
	case transport == nil:
		log.Info("colibri client operator, first segment reservation setup", "egress", egressID)
	case transport.Type() == colpath.PathType:
		if libcol.Tick(transport.InfoField.ExpTick).ToTime().Before(time.Now()) {
			// If the active index we have is expired, don't use it
			break
		}
		// prepare remote address with the new path
		rAddr.Path = snetpath.Colibri{
			ColibriPathMinimal: *transport,
		}
	default:
		// nothing but colibri or nil is accepted
		return nil, serrors.New("error in client operator: not a valid transport",
			"path_type", transport.Type())
	}
	return rAddr, nil
}

func (o *ServiceClientOperator) colibriClient(ctx context.Context, rAddr *snet.UDPAddr) (
	colpb.ColibriServiceClient, error) {

	log.Debug("deleteme about to dial at the operator")
	conn, err := o.gRPCDialer.Dial(ctx, rAddr)
	if err != nil {
		log.Info("error dialing a grpc connection", "addr", rAddr, "err", err)
		return nil, err
	}
	return colpb.NewColibriServiceClient(conn), nil
}

func (o *ServiceClientOperator) debugClient(ctx context.Context, rAddr *snet.UDPAddr) (
	colpb.ColibriDebugServiceClient, error) {

	conn, err := o.gRPCDialer.Dial(ctx, rAddr)
	if err != nil {
		log.Info("error dialing a grpc connection", "addr", rAddr, "err", err)
		return nil, err
	}
	return colpb.NewColibriDebugServiceClient(conn), nil
}

func (o *ServiceClientOperator) neighborAddr(egressID uint16) (*snet.UDPAddr, bool) {
	o.neighboringColSvcsMu.Lock()
	defer o.neighboringColSvcsMu.Unlock()

	addr, ok := o.neighboringColSvcs[egressID]
	return addr, ok
}

// initialize waits in the background until this operator can obtain paths to all the remaining IAs.
func (o *ServiceClientOperator) initialize(topo TopoLoader) {
	o.neighboringIAs = neighbors(topo)
	o.neighboringIAs[0] = topo.IA() // interface with ID 0 is ourselves
	// a new local copy to find their addresses and keep track of the remaining neighbors
	remainingIAs := neighbors(topo)
	go func() {
		defer log.HandlePanic()
		log.Info("will initialize colibri client operator", "neighbor_count", len(remainingIAs))

		for len(remainingIAs) > 0 {
			log.Debug("colibri client operator initializing", "remaining", len(remainingIAs))
			newNeighbors := make(map[uint16]*snet.UDPAddr)
			remainingIAs = o.findNeighbors(newNeighbors, remainingIAs)
			if len(newNeighbors) > 0 {
				o.neighboringColSvcsMu.Lock()
				for egressID, addr := range newNeighbors {
					o.neighboringColSvcs[egressID] = addr
				}
				o.neighboringColSvcsMu.Unlock()
			}
			if len(remainingIAs) > 0 {
				time.Sleep(2 * time.Second)
			}
		}
		o.neighboringColSvcsMu.Lock()
		o.initialized = true
		o.neighboringColSvcsMu.Unlock()
		log.Info("colibri client operator initialization complete")
		go func() {
			defer log.HandlePanic()
			o.periodicResolveNeighbors(topo)
		}()
		o.periodicDiscoverServices()
	}()
}

// periodicResolveNeighbors periodically scans the topology and gets new paths for the neighbors.
func (o *ServiceClientOperator) periodicResolveNeighbors(topo TopoLoader) {
	for {
		time.Sleep(15 * time.Minute)
		neighbors := neighbors(topo)
		log.Debug("colibri client operator periodically finding neighbors",
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
			log.Info("error periodic resolve neighbors: neighbors without address",
				"missing_count", len(remainingIAs), "total", len(neighbors),
				"missing", strings.Join(missing, ","))
		} else {
			o.neighboringColSvcsMu.Lock()
			o.neighboringColSvcs = newAddrBook
			o.neighboringColSvcsMu.Unlock()
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
func neighbors(topo TopoLoader) map[uint16]addr.IA {
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
	Router     snet.Router
	GRPCDialer grpc.Dialer
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
	conn, err := r.GRPCDialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.ColibriServices(ctx, &dpb.ColibriServicesRequest{})
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
