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

// XXX(matzf) this should be an internal library in colibri (used both for lib/colibri and co/)
package drkeyutil

import (
	"context"
	"crypto/aes"
	"crypto/subtle"

	"github.com/dchest/cmac"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ComputeAuthenticators returns the authenticators obtained to apply a MAC function to the
// same payload.
func ComputeAuthenticators(payload []byte, keys []drkey.Key) ([][]byte, error) {
	auths := make([][]byte, len(keys))
	for i, k := range keys {
		var err error
		auths[i], err = MAC(payload, k)
		if err != nil {
			return nil, err
		}
	}
	return auths, nil
}

// ValidateAuthenticators validates each authenticators[i] against MAC(payload[i], keys[i]).
// Returns error if the MAC function returns any error, or true/false if each of the authenticators
// matches the result of each MAC function invocation.
func ValidateAuthenticators(payloads [][]byte, keys []drkey.Key, authenticators [][]byte) (
	bool, error) {

	if len(payloads) != len(keys) || len(keys) != len(authenticators) {
		return false, serrors.New("wrong lengths (must be the same)")
	}
	for i := range keys {
		mac, err := MAC(payloads[i], keys[i])
		if err != nil {
			return false, serrors.WrapStr("MAC function", err)
		}
		if subtle.ConstantTimeCompare(mac, authenticators[i]) != 1 {
			return false, nil
		}
	}
	return true, nil
}

func MAC(payload []byte, key drkey.Key) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, serrors.WrapStr("initializing aes cipher", err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.WrapStr("initializing cmac", err)
	}
	_, err = mac.Write(payload)
	if err != nil {
		return nil, serrors.WrapStr("preparing mac", err)
	}
	return mac.Sum(nil), nil
}

// XXX(matzf) this interface should be moved to lib/colibri, where it's used
type DRKeyGetLvl2Keyer interface {
	DRKeyGetASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	DRKeyGetHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error)
	DRKeyGetHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
}
