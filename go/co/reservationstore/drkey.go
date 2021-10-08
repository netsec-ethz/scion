// Copyright 2021 ETH Zurich, Anapaya Systems
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

package reservationstore

import (
	"context"
	"hash"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/drkey"
)

type Authenticator interface {
	macComputer
	macVerifier
}

type macComputer interface {
	// SegmentRequestInitialMAC computes the MAC for the immutable fields of the request,
	// for each AS in transit. This MAC is only computed at the first AS.
	// The initial AS is obtained from the first step of the path of the request.
	ComputeSegmentRequestInitialMAC(ctx context.Context, req *segment.SetupReq) error
}

type macVerifier interface {
	// SegmentRequestInitialMAC verifies the validity of the source authentication created
	// by the initial AS for this particular transit AS as.
	// Returns
	ValidateSegmentRequestInitialMAC(ctx context.Context, req *segment.SetupReq, as addr.IA) (
		bool, error)
}

// DrkeyAuthenticator implements macComputer and macVerifier using DRKey.
type DrkeyAuthenticator struct {
	connector daemon.Connector // to obtain level 1 & 2 keys
}

func (a *DrkeyAuthenticator) ComputeSegmentRequestInitialMAC(ctx context.Context, src addr.IA, req *segment.SetupReq) error {
	keys, err := a.slowAS2ASFromPath(ctx, src, req.PathAtSource)
	if err != nil {
		return err
	}
	macCodes := make([][]byte, len(req.PathAtSource.Steps))
	assert(len(keys) == len(req.PathAtSource.Steps)-1, "bad key set with length %d (should be %d)",
		len(keys), len(req.PathAtSource.Steps)-1)
	for i, step := range req.PathAtSource.Steps {
		if i == 0 {
			macCodes[i] = nil
		}
		key := keys[step.IA]
		// TODO(juagargi) deleteme compute MAC using key and store it in macCodes[i]
		var mac hash.Hash
		macCodes[i] = key
	}
	return nil
}

// slowLvl1FromPath gets the L1 keys from the slow side to all ASes in the path.
func (a *DrkeyAuthenticator) slowAS2ASFromPath(ctx context.Context, src addr.IA,
	path *base.TransparentPath) (map[addr.IA][]byte, error) {

	keys := make(map[addr.IA][]byte)
	for _, step := range path.Steps {
		if step.IA.Equal(src) {
			continue // skip the reservation initiator
		}
		key, err := a.getDRKeyAS2AS(ctx, step.IA, src)
		if err != nil {
			return nil, err
		}
		keys[step.IA] = key
	}
	return keys, nil
}

func (a *DrkeyAuthenticator) getDRKeyAS2AS(ctx context.Context, fast, slow addr.IA) (
	[]byte, error) {

	meta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: "piskes",
		SrcIA:    fast,
		DstIA:    slow,
	}

	lvl2Key, err := a.connector.DRKeyGetLvl2Key(ctx, meta, time.Now())
	if err != nil {
		return nil, err
	}
	return lvl2Key.Key, nil
}

func MAC(payload []byte) ([]byte, error) {

}
