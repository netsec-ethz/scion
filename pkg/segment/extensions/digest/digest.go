// Copyright 2020 ETH Zurich
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

package digest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
)

type Digest struct {
	Digest []byte
}

const DigestLength = 16

type Extension struct {
	// Epic denotes the digest of the EpicDetachedExtension
	Epic Digest
	// Fabrid denotes the hash of both the supported indices map, as well as the
	// index to identifier map.
	Fabrid Digest
}

func ExtensionFromPB(d *cppb.DigestExtension) *Extension {
	if d == nil {
		return nil
	}
	var epic Digest
	var fabrid Digest
	if d.Epic == nil {
		epic = Digest{}
	} else {
		e := make([]byte, DigestLength)
		copy(e, d.Epic.Digest)
		epic = Digest{Digest: e}
	}
	if d.Fabrid == nil {
		fabrid = Digest{}
	} else {
		e := make([]byte, DigestLength)
		copy(e, d.Fabrid.Digest)
		fabrid = Digest{Digest: e}
	}
	return &Extension{
		Epic:   epic,
		Fabrid: fabrid,
	}
}

func ExtensionToPB(d *Extension) *cppb.DigestExtension {
	if d == nil {
		return nil
	}
	e := make([]byte, DigestLength)
	copy(e, d.Epic.Digest)

	f := make([]byte, DigestLength)
	copy(f, d.Fabrid.Digest)
	return &cppb.DigestExtension{
		Epic: &cppb.DigestExtension_Digest{
			Digest: e,
		},
		Fabrid: &cppb.DigestExtension_Digest{
			Digest: f,
		},
	}
}

func (d *Digest) Set(input []byte) {
	d.Digest = calculateDigest(input)
}

func (d *Digest) Validate(input []byte) error {
	b := calculateDigest(input)
	if !bytes.Equal(b, d.Digest) {
		return serrors.New("digest validation failed", "calculated", hex.EncodeToString(b),
			"stored", hex.EncodeToString(d.Digest))
	}
	return nil
}

func calculateDigest(input []byte) []byte {
	h := sha256.New()
	h.Write(input)
	return h.Sum(nil)[0:DigestLength]
}
