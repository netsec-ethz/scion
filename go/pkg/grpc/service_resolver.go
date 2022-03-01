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

package grpc

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

type ServiceResolver interface {
	ResolveTrustService(context.Context, *snet.SVCAddr) (*snet.UDPAddr, error)
	ResolveDRKeyService(context.Context, *snet.SVCAddr) (*snet.UDPAddr, error)
	ResolveSegmentLookupService(context.Context, *snet.SVCAddr) (*snet.UDPAddr, error)
	ResolveSegmentRegService(context.Context, *snet.SVCAddr) (*snet.UDPAddr, error)
	ResolveChainRenewalService(context.Context, *snet.SVCAddr) (*snet.UDPAddr, error)
}

type DSResolver struct {
	Dialer Dialer
}

func RouteToDS(router snet.Router, ia addr.IA) (*snet.SVCAddr, error) {
	path, err := router.Route(context.Background(), ia)
	if err != nil || path == nil {
		return nil, serrors.New("no route to IA", "ia", ia, "err", err, "path", path)
	}

	return &snet.SVCAddr{
		IA:      ia,
		Path:    path.Path(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcDS,
	}, nil
}

func (r *DSResolver) ResolveTrustService(ctx context.Context, ds *snet.SVCAddr) (
	*snet.UDPAddr, error) {

	conn, err := r.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.CSRPCs(ctx, &dpb.CSRequest{}, RetryProfile...)
	if err != nil {
		return nil, serrors.WrapStr("discovering CS services", err)
	}
	if len(rep.TrustMaterial) == 0 {
		return nil, serrors.New("no trust material services discovered", "ia", ds.IA.String())
	}

	host, err := net.ResolveUDPAddr("udp", rep.TrustMaterial[0])
	if err != nil {
		return nil, serrors.WrapStr("parsing udp address for trust material service", err,
			"udp", rep.TrustMaterial[0])
	}

	return &snet.UDPAddr{
		IA:      ds.IA,
		Path:    ds.Path,
		NextHop: ds.NextHop,
		Host:    host,
	}, nil
}

func (r *DSResolver) ResolveSegmentLookupService(ctx context.Context, ds *snet.SVCAddr) (
	*snet.UDPAddr, error) {

	conn, err := r.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.CSRPCs(ctx, &dpb.CSRequest{}, RetryProfile...)
	if err != nil {
		return nil, serrors.WrapStr("discovering CS services", err)
	}
	if len(rep.SegmentLookup) == 0 {
		return nil, serrors.New("no seg lookup services discovered", "ia", ds.IA.String())
	}

	host, err := net.ResolveUDPAddr("udp", rep.SegmentLookup[0])
	if err != nil {
		return nil, serrors.WrapStr("parsing udp address for segment lookup", err,
			"udp", rep.TrustMaterial[0])
	}

	return &snet.UDPAddr{
		IA:      ds.IA,
		Path:    ds.Path,
		NextHop: ds.NextHop,
		Host:    host,
	}, nil
}

func (r *DSResolver) ResolveSegmentRegService(ctx context.Context, ds *snet.SVCAddr) (
	*snet.UDPAddr, error) {

	conn, err := r.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.CSRPCs(ctx, &dpb.CSRequest{}, RetryProfile...)
	if err != nil {
		return nil, serrors.WrapStr("discovering CS services", err)
	}
	if len(rep.SegmentRegistration) == 0 {
		return nil, serrors.New("no seg reg services discovered", "ia", ds.IA.String())
	}

	host, err := net.ResolveUDPAddr("udp", rep.SegmentRegistration[0])
	if err != nil {
		return nil, serrors.WrapStr("parsing udp address for segment reg", err,
			"udp", rep.SegmentRegistration[0])
	}

	return &snet.UDPAddr{
		IA:      ds.IA,
		Path:    ds.Path,
		NextHop: ds.NextHop,
		Host:    host,
	}, nil
}

func (r *DSResolver) ResolveChainRenewalService(ctx context.Context, ds *snet.SVCAddr) (
	*snet.UDPAddr, error) {
	conn, err := r.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.CSRPCs(ctx, &dpb.CSRequest{}, RetryProfile...)
	if err != nil {
		return nil, serrors.WrapStr("discovering CS services", err)
	}
	if len(rep.ChainRenewal) == 0 {
		return nil, serrors.New("no chain renewal service discovered", "ia", ds.IA.String())
	}

	host, err := net.ResolveUDPAddr("udp", rep.ChainRenewal[0])
	if err != nil {
		return nil, serrors.WrapStr("parsing udp address for chain renewal service", err,
			"udp", rep.TrustMaterial[0])
	}

	return &snet.UDPAddr{
		IA:      ds.IA,
		Path:    ds.Path,
		NextHop: ds.NextHop,
		Host:    host,
	}, nil
}

func (r *DSResolver) ResolveDRKeyService(ctx context.Context, ds *snet.SVCAddr) (
	*snet.UDPAddr, error) {

	conn, err := r.Dialer.Dial(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dpb.NewDiscoveryServiceClient(conn)
	rep, err := client.CSRPCs(ctx, &dpb.CSRequest{}, RetryProfile...)
	if err != nil {
		return nil, serrors.WrapStr("discovering CS services", err)
	}
	if len(rep.DrkeyInter) == 0 {
		return nil, serrors.New("no drkey service discovered", "ia", ds.IA.String())
	}

	host, err := net.ResolveUDPAddr("udp", rep.DrkeyInter[0])
	if err != nil {
		return nil, serrors.WrapStr("parsing udp address for drkey service", err,
			"udp", rep.DrkeyInter[0])
	}

	return &snet.UDPAddr{
		IA:      ds.IA,
		Path:    ds.Path,
		NextHop: ds.NextHop,
		Host:    host,
	}, nil
}
