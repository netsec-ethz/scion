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

package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	csdrkey "github.com/scionproto/scion/go/pkg/cs/drkey"
)

func getTestMasterSecret() []byte {
	return []byte{0, 1, 2, 3}
}

// SecretValueTestFactory works as a SecretValueFactory but uses a user-controlled-variable instead
// of time.Now when calling GetSecretValue.
type SecretValueTestFactory struct {
	csdrkey.SecretValueFactory
	Now time.Time
}

func (f *SecretValueTestFactory) GetSecretValue(_ time.Time) (drkey.SV, error) {
	return f.SecretValueFactory.GetSecretValue(f.Now)
}

func GetSecretValueTestFactory() drkeystorage.SecretValueFactory {
	return &SecretValueTestFactory{
		SecretValueFactory: *csdrkey.NewSecretValueFactory(getTestMasterSecret(), 10*time.Second),
		Now:                util.SecsToTime(0),
	}
}

func GetInputToDeriveLvl2Key(t *testing.T) (drkey.Lvl2Meta, drkey.Lvl1Key) {
	srcIA := xtest.MustParseIA("1-ff00:0:1")
	dstIA := xtest.MustParseIA("1-ff00:0:2")
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	sv, err := GetSecretValueTestFactory().GetSecretValue(util.SecsToTime(0))
	require.NoError(t, err)

	lvl1Key := drkey.Lvl1Key{
		Key: k,
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: sv.Epoch,
			SrcIA: srcIA,
			DstIA: dstIA,
		},
	}

	var srcHost addr.HostAddr = addr.HostNone{}
	var dstHost addr.HostAddr = addr.HostNone{}
	meta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: "scmp",
		Epoch:    lvl1Key.Epoch,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
	}
	return meta, lvl1Key
}
