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
	"fmt"

	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/log"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

type DebugService struct {
	Store reservationstorage.Store
}

var _ colpb.ColibriDebugCommandsServer = (*DebugService)(nil)

func (s *DebugService) EchoWithSegr(ctx context.Context, req *colpb.EchoWithSegrRequest,
) (*colpb.EchoWithSegrResponse, error) {

	fmt.Println("echoing ...")
	log.Debug("deleteme echoing ...")
	res := &colpb.EchoWithSegrResponse{}
	return res, nil
}
