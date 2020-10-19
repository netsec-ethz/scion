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

package grpc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	dk_grpc "github.com/scionproto/scion/go/pkg/cs/drkey/grpc"
	"github.com/scionproto/scion/go/pkg/cs/drkey/test"
)

func TestDeriveLvl2Key(t *testing.T) {

	expectedKey := xtest.MustParseHexString("b90ceff1586e5b5cc3313445df18f271")

	meta, lvl1Key := test.GetInputToDeriveLvl2Key(t)

	lvl2Key, err := dk_grpc.DeriveLvl2(meta, lvl1Key)
	require.NoError(t, err)
	require.EqualValues(t, expectedKey, lvl2Key.Key)
}
