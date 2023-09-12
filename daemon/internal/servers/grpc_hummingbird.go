// Copyright 2023 ETH Zurich
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

package servers

import (
	"context"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

func (s *DaemonServer) StoreFlyovers(
	ctx context.Context,
	req *sdpb.StoreFlyoversRequest,
) (*sdpb.StoreFlyoversResponse, error) {

	// Translate flyovers from protobuf and store them.
	err := s.FlyoverDB.StoreFlyovers(ctx, hummingbird.ConvertFlyoversFromPB(req.Flyovers))
	if err != nil {
		return nil, err
	}

	return &sdpb.StoreFlyoversResponse{}, nil
}
func (s *DaemonServer) ListFlyovers(
	ctx context.Context,
	req *sdpb.ListFlyoversRequest,
) (*sdpb.ListFlyoversResponse, error) {

	// Get all flyovers.
	flyovers, err := s.FlyoverDB.GetFlyovers(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &sdpb.ListFlyoversResponse{
		Flyovers: hummingbird.ConvertFlyoversToPB(flyovers),
	}, nil
}

func (s *DaemonServer) GetReservations(
	ctx context.Context,
	req *sdpb.GetReservationsRequest,
) (*sdpb.GetReservationsResponse, error) {

	// Get SCION paths.
	paths, err := s.getScionPaths(ctx, addr.IA(req.SourceIsdAs), addr.IA(req.DestinationIsdAs),
		req.Refresh)
	if err != nil {
		return nil, err
	}

	// Obtain reservations composing flyovers for those paths.
	rsvs, err := s.getReservations(ctx, paths, time.Now(), uint16(req.MinBandwidth))
	if err != nil {
		return nil, err
	}

	// Prepare response.
	res := &sdpb.GetReservationsResponse{
		Reservations: make([]*sdpb.Reservation, len(paths)),
	}
	for i := range res.Reservations {
		res.Reservations[i], err = hummingbird.ConvertReservationToPB(rsvs[i])
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (s *DaemonServer) getScionPaths(
	ctx context.Context,
	src, dst addr.IA,
	refresh bool,
) ([]path.Path, error) {
	pathReq := &sdpb.PathsRequest{
		SourceIsdAs:      uint64(src),
		DestinationIsdAs: uint64(dst),
		Refresh:          refresh,
		Hidden:           false,
	}
	pathRes, err := s.paths(ctx, pathReq)
	err = unwrapMetricsError(err)
	if err != nil {
		return nil, serrors.WrapStr("obtaining reservations", err)
	}

	// Unwrap the response to a slice of path.Path
	paths := make([]path.Path, len(pathRes.Paths))
	for i, p := range pathRes.Paths {
		paths[i], err = convertPath(p, dst)
		if err != nil {
			return nil, err
		}
	}

	return paths, nil
}

func (s *DaemonServer) getReservations(
	ctx context.Context,
	paths []path.Path,
	now time.Time,
	minBW uint16,
) ([]*hummingbird.Reservation, error) {

	// Make a set with all appearing IASet. Then a slice of them to obtain flyovers.
	IASet := make(map[addr.IA]struct{}, 0)
	for _, p := range paths {
		for _, iface := range p.Meta.Interfaces {
			IASet[iface.IA] = struct{}{}
		}
	}
	IAs := make([]addr.IA, 0, len(IASet))
	for ia := range IASet {
		IAs = append(IAs, ia)
	}

	// Get flyovers on any AS present in the paths.
	flyovers, err := s.FlyoverDB.GetFlyovers(ctx, IAs)
	if err != nil {
		return nil, err
	}
	mFlyovers := hummingbird.FlyoversToMap(flyovers)

	// For each path, try to assign as many flyovers as possible.
	reservations := make([]*hummingbird.Reservation, len(paths))
	for i, p := range paths {
		reservations[i], err = hummingbird.NewReservation(
			hummingbird.WithNow(now),
			hummingbird.WithMinBW(minBW),
			hummingbird.WithScionPath(p, mFlyovers),
		)
		if err != nil {
			return nil, err
		}
	}

	// Rank the reservations by flyover / hop ratio.
	sort.Slice(reservations, func(i, j int) bool {
		nFa, nHFa := reservations[i].FlyoverAndHFCount()
		ratioa := float64(nFa) / float64(nHFa)
		nFb, nHFb := reservations[i].FlyoverAndHFCount()
		ratiob := float64(nFb) / float64(nHFb)

		return ratioa < ratiob
	})

	return reservations, nil
}

func convertPath(p *sdpb.Path, dst addr.IA) (path.Path, error) {
	expiry := time.Unix(p.Expiration.Seconds, int64(p.Expiration.Nanos))
	if len(p.Interfaces) == 0 {
		return path.Path{
			Src: dst,
			Dst: dst,
			Meta: snet.PathMetadata{
				MTU:    uint16(p.Mtu),
				Expiry: expiry,
			},
			DataplanePath: path.Empty{},
		}, nil
	}
	underlayA, err := net.ResolveUDPAddr("udp", p.Interface.Address.Address)
	if err != nil {
		return path.Path{}, serrors.WrapStr("resolving underlay", err)
	}
	interfaces := make([]snet.PathInterface, len(p.Interfaces))
	for i, pi := range p.Interfaces {
		interfaces[i] = snet.PathInterface{
			ID: common.IFIDType(pi.Id),
			IA: addr.IA(pi.IsdAs),
		}
	}
	latency := make([]time.Duration, len(p.Latency))
	for i, v := range p.Latency {
		latency[i] = time.Second*time.Duration(v.Seconds) + time.Duration(v.Nanos)
	}
	geo := make([]snet.GeoCoordinates, len(p.Geo))
	for i, v := range p.Geo {
		geo[i] = snet.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]snet.LinkType, len(p.LinkType))
	for i, v := range p.LinkType {
		linkType[i] = linkTypeFromPB(v)
	}

	res := path.Path{
		Src: interfaces[0].IA,
		Dst: dst,
		DataplanePath: path.SCION{
			Raw: p.Raw,
		},
		NextHop: underlayA,
		Meta: snet.PathMetadata{
			Interfaces:   interfaces,
			MTU:          uint16(p.Mtu),
			Expiry:       expiry,
			Latency:      latency,
			Bandwidth:    p.Bandwidth,
			Geo:          geo,
			LinkType:     linkType,
			InternalHops: p.InternalHops,
			Notes:        p.Notes,
		},
	}

	if p.EpicAuths == nil {
		return res, nil
	}
	res.Meta.EpicAuths = snet.EpicAuths{
		AuthPHVF: append([]byte(nil), p.EpicAuths.AuthPhvf...),
		AuthLHVF: append([]byte(nil), p.EpicAuths.AuthLhvf...),
	}
	return res, nil
}

func linkTypeFromPB(lt sdpb.LinkType) snet.LinkType {
	switch lt {
	case sdpb.LinkType_LINK_TYPE_DIRECT:
		return snet.LinkTypeDirect
	case sdpb.LinkType_LINK_TYPE_MULTI_HOP:
		return snet.LinkTypeMultihop
	case sdpb.LinkType_LINK_TYPE_OPEN_NET:
		return snet.LinkTypeOpennet
	default:
		return snet.LinkTypeUnset
	}
}
