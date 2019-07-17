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
	"testing"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
)

func getTestSV() *drkey.DRKeySV {
	return &drkey.DRKeySV{
		Epoch: drkey.Epoch{
			Begin: 0,
			End:   1,
		},
		Key: common.RawBytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
}

func loadCertsKeys(t *testing.T) (*cert.Certificate, common.RawBytes, *cert.Certificate, common.RawBytes) {
	loadChain := func(filename string, t *testing.T) *cert.Chain {
		chain, err := cert.ChainFromFile(filename, false)
		if err != nil {
			t.Fatalf("Error loading Certificate from '%s': %v", filename, err)
		}
		return chain
	}
	cert111 := loadChain("testdata/as111/certs/ISD1-ASff00_0_111-V1.crt", t).Leaf
	privateKey111, _ := keyconf.LoadKey("testdata/as111/keys/as-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
	cert112 := loadChain("testdata/as112/certs/ISD1-ASff00_0_112-V1.crt", t).Leaf
	privateKey112, _ := keyconf.LoadKey("testdata/as112/keys/as-decrypt.key", scrypto.Curve25519xSalsa20Poly1305)
	return cert111, privateKey111, cert112, privateKey112
}

func ia(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic("Unexpected bad IA")
	}
	return ia
}
