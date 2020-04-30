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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/util"
)

const drkeySalt = "Derive DRKey Key" // same as in Python

// SVMeta represents the information about a DRKey secret value.
type SVMeta struct {
	Epoch Epoch
}

// SV represents a DRKey secret value.
type SV struct {
	SVMeta
	Key DRKey
}

// Equal returns true if both secret values are identical.
func (sv SV) Equal(other SV) bool {
	return sv.Epoch.Equal(other.Epoch) && bytes.Compare(sv.Key, other.Key) == 0
}

// DeriveSV constructs a valid SV. asSecret is typically the AS master secret.
func DeriveSV(meta SVMeta, asSecret []byte) (SV, error) {
	msLen := len(asSecret)
	if msLen == 0 {
		return SV{}, errors.New("Invalid zero sized secret")
	}
	all := make([]byte, 1+msLen+8)
	copy(all, []byte{byte(msLen)})
	copy(all[1:], asSecret)
	binary.LittleEndian.PutUint32(all[msLen+1:], util.TimeToSecs(meta.Epoch.NotBefore.Time))
	binary.LittleEndian.PutUint32(all[msLen+5:], util.TimeToSecs(meta.Epoch.NotAfter.Time))

	key := pbkdf2.Key(all, []byte(drkeySalt), 1000, 16, sha256.New)
	return SV{
		SVMeta: meta,
		Key:    DRKey(key),
	}, nil
}
