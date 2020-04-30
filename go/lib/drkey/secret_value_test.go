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

package drkey

import (
	"encoding/hex"
	"testing"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestDeriveSV(t *testing.T) {
	meta := SVMeta{NewEpoch(0, 1)}
	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	targetKey := xtest.MustParseHexString("47bfbb7d94706dc9e79825e5a837b006")

	got, err := DeriveSV(meta, asSecret)
	if err != nil {
		t.Errorf("DeriveSV() error = %v", err)
		return
	}
	if !got.Key.Equal(targetKey) {
		t.Fatalf("Unexpected sv key: %s, expected: %s",
			hex.EncodeToString(got.Key), hex.EncodeToString(targetKey))
	}
}
