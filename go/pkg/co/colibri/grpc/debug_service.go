// Copyright 2022 ETH Zurich
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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/log"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

type DebugService struct {
	Store reservationstorage.Store
	DB    backend.DB
}

var _ colpb.ColibriDebugCommandsServer = (*DebugService)(nil)

func (s *DebugService) EchoWithSegr(ctx context.Context, req *colpb.EchoWithSegrRequest,
) (*colpb.EchoWithSegrResponse, error) {

	id := translate.ID(req.Id)
	log.Info("debug server echo with Segr", "segr", id.String())
	res := &colpb.EchoWithSegrResponse{
		Error: true,
	}

	segR, err := s.DB.GetSegmentRsvFromID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error retrieving segment: %s", err)
	}
	if segR == nil {
		return nil, status.Errorf(codes.NotFound, "segment not found: %s", id)
	}

	log.Debug("deleteme do actually perform a call via the Store that traverses the segment", "segr id", segR)

	// success
	res.Error = false
	return res, nil
}
