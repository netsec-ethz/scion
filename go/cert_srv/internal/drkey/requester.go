// Copyright 2019 ETH Zurich
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

package drkey

import (
	"context"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/periodic"
)

var _ periodic.Task = (*Requester)(nil)

// Requester is in charge of getting the L1 keys before they expire
type Requester struct {
	Msgr  infra.Messenger
	State *config.State
	IA    addr.IA
}

// Run requests L1 keys from other CSs
func (r *Requester) Run(ctx context.Context) {
	//
}

// getASesToContact returns the list of ASes we have to query for their L1 keys
func (r *Requester) getASesToContact() {

}
