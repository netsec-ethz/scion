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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
)

const drkeySalt = "Derive DRKey Key" // same as in Python

// DRKey represents a raw binary key
type DRKey struct {
	Key common.RawBytes
}

// type DRKey common.RawBytes

func (k *DRKey) String() string {
	return fmt.Sprintf("%v", "[redacted key]")
}

// SVMeta represents the information about a DRKey secret value
type SVMeta struct {
	Epoch Epoch
}

func (k *SVMeta) String() string {
	return fmt.Sprintf("%v", k.Epoch)
}

// SV represents a DRKey secret value
type SV struct {
	SVMeta
	DRKey
}

func (k *SV) String() string {
	return fmt.Sprintf("%v %v", k.SVMeta, k.DRKey)
}

// NewSV constructs a valid SV. asSecret is typically the AS master secret
func NewSV(meta SVMeta, asSecret common.RawBytes) (SV, error) {
	msLen := len(asSecret)
	if msLen == 0 {
		return SV{}, errors.New("Invalid zero sized secret")
	}
	all := make(common.RawBytes, msLen+8)
	_, err := asSecret.WritePld(all[:msLen])
	if err != nil {
		return SV{}, err
	}
	binary.LittleEndian.PutUint32(all[msLen:], meta.Epoch.BeginAsSeconds())
	binary.LittleEndian.PutUint32(all[msLen+4:], meta.Epoch.EndAsSeconds())
	key := pbkdf2.Key(all, []byte(drkeySalt), 1000, 16, sha256.New)
	return SV{
		SVMeta: meta,
		DRKey:  DRKey{key},
	}, nil
}
