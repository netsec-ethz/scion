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

package daemon

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
)

func (c grpcConn) StoreFlyovers(
	ctx context.Context,
	flyovers []*hummingbird.Flyover,
) error {

	client := sdpb.NewDaemonServiceClient(c.conn)
	_, err := client.StoreFlyovers(ctx, &sdpb.StoreFlyoversRequest{
		Flyovers: hummingbird.ConvertFlyoversToPB(flyovers),
	})

	return err
}

func (c grpcConn) ListFlyovers(ctx context.Context,
) ([]*hummingbird.Flyover, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	res, err := client.ListFlyovers(ctx, &sdpb.ListFlyoversRequest{})
	if err != nil {
		return nil, err
	}
	return hummingbird.ConvertFlyoversFromPB(res.Flyovers), nil
}

func (c grpcConn) GetReservations(
	ctx context.Context,
	src addr.IA,
	dst addr.IA,
	minBW uint16,
	refresh bool,
) ([]*hummingbird.Reservation, error) {

	client := sdpb.NewDaemonServiceClient(c.conn)
	res, err := client.GetReservations(ctx, &sdpb.GetReservationsRequest{
		SourceIsdAs:      uint64(src),
		DestinationIsdAs: uint64(dst),
		MinBandwidth:     uint32(minBW),
		Refresh:          refresh,
	})
	if err != nil {
		return nil, err
	}

	// Return those reservations.
	if res == nil {
		return nil, nil
	}
	return hummingbird.ConvertReservationsFromPB(res.Reservations)
}
