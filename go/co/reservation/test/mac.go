// Copyright 2022 ETH Zurich, Anapaya Systems
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
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// InitColibriKeys initializes N colibri keys (N should be the number of ASes). Note that this
// function uses math.rand. thus it should be deterministically seeded before using it.
func InitColibriKeys(t *testing.T, N int) []cipher.Block {
	buff := make([]byte, 16)
	colibriKeys := make([]cipher.Block, N)
	for i := 0; i < N; i++ {
		_, err := rand.Read(buff)
		require.NoError(t, err)
		colibriKeys[i], err = libcolibri.InitColibriKey(buff)
		require.NoError(t, err)
	}
	return colibriKeys
}

// ComputeMACs returns N MAC codes. Each MAC code is 4 bytes, and N is the number of steps the
// reservation has.
func ComputeMACs(t *testing.T, path *colpath.ColibriPath, colibriKeysPerAS []cipher.Block,
	srcAS, dstAS addr.AS) [][4]byte {

	t.Helper()
	N := len(colibriKeysPerAS)
	require.Equal(t, N, int(path.InfoField.HFCount))
	require.Len(t, path.HopFields, N)
	MACs := make([][4]byte, N)
	for i := 0; i < N; i++ {
		hf := &reservation.HopField{
			Ingress: path.HopFields[i].IngressId,
			Egress:  path.HopFields[i].EgressId,
		}
		key := colibriKeysPerAS[i]
		MACs[i] = computeMAC(t,
			key,
			path.InfoField.ResIdSuffix,
			reservation.Tick(path.InfoField.ExpTick),
			reservation.IndexNumber(path.InfoField.Ver),
			reservation.BWCls(path.InfoField.BwCls),
			reservation.RLC(path.InfoField.Rlc),
			hf,
			srcAS,
			dstAS,
			path.InfoField.R,
		)
	}
	return MACs
}

// VerifyMACs verifies each one of the hop field MACs, or FailNow otherwise.
// colibriKeysPerAS follows the order of the ASes in the SegR (not necesarely, the same one
// as in the HF, for example if the path.InfoField.R == true ).
func VerifyMACs(t *testing.T, path *colpath.ColibriPath, colibriKeysPerAS []cipher.Block,
	srcAS, dstAS addr.AS) {

	t.Helper()
	MACs := ComputeMACs(t, path, colibriKeysPerAS, srcAS, dstAS)
	for i, MAC := range MACs {
		assert.Equal(t, MAC[:], path.HopFields[i].Mac)
	}
}

// TraverseASesAndStampMACs computes the MACs and writes them into each one of the hop fields.
func TraverseASesAndStampMACs(t *testing.T, r *segment.Reservation, colibriKeysPerAS []cipher.Block,
	srcAS, dstAS addr.AS) {

	t.Helper()
	index := r.ActiveIndex()
	require.NotNil(t, index)

	N := len(r.Steps)
	require.Len(t, index.Token.HopFields, N)
	require.LessOrEqual(t, r.CurrentStep, N)

	for i := 0; i < N; i++ {
		index.Token.HopFields[i].Mac = computeMAC(t,
			colibriKeysPerAS[i],
			r.ID.Suffix, index.Token.ExpirationTick,
			index.Idx,
			index.AllocBW,
			index.Token.RLC,
			&index.Token.HopFields[i],
			srcAS,
			dstAS,
			false, // MACs are always computed at admission -> always direction of the traffic
		)
	}
}

// computeMAC returns the hop field MAC as 4 bytes.
func computeMAC(t *testing.T, key cipher.Block, suffix []byte, expTick reservation.Tick,
	idx reservation.IndexNumber, bwCls reservation.BWCls, rlc reservation.RLC,
	hf *reservation.HopField, srcAS, dstAS addr.AS, R bool) [4]byte {

	const isE2E = false
	var input [libcolibri.LengthInputDataRound16]byte
	libcolibri.MACInputStatic(
		input[:],
		suffix,
		uint32(expTick),
		bwCls,
		rlc,
		/* C */ !isE2E,
		/* R */ R,
		idx,
		srcAS,
		dstAS,
		hf.Ingress,
		hf.Egress)

	var MAC [4]byte
	err := libcolibri.MACStaticFromInput(MAC[:], key, input[:])
	require.NoError(t, err)
	fmt.Printf("computeMAC input = %s mac = %s\n",
		hex.EncodeToString(input[:]), hex.EncodeToString(MAC[:]))
	return MAC
}

// var zeroInitVector [aes.BlockSize]byte

// func initColibriMac(key cipher.Block) (cipher.BlockMode, error) {
// 	// CBC-MAC = CBC-Encryption with zero initialization vector
// 	mode := cipher.NewCBCEncrypter(key, zeroInitVector[:])
// 	return mode, nil
// }
