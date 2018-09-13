// Copyright 2018 ETH Zurich
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

package main

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	DRKeyHandlerTimeout = 5 * time.Second
)

// DRKeyHandler handles drkey requests and replies.
type DRKeyHandler struct{}

func (h *DRKeyHandler) Handle(r *infra.Request) {
	// Bind the handler to a snapshot of the current config
	h.HandleReq(r, conf.Get())
}

func (h *DRKeyHandler) HandleReq(r *infra.Request, config *conf.Conf) {
	ctx, cancelF := context.WithTimeout(r.Context(), DRKeyHandlerTimeout)
	defer cancelF()

	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl1Req)
	signed := r.FullMessage.(*ctrl.SignedPld)

	log.Debug("[DRKeyHandler] Received drkey lvl1 request", "addr", saddr, "req", req)
	// TODO(ben): remove
	log.Debug("[DRKeyHandler], additional info", "context", ctx, "signed request", signed)
	// TODO(ben): validate signature

	// TODO(ben): validate request (validity time, etc.)
}
