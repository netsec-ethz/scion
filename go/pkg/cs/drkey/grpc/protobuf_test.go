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
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	dk_grpc "github.com/scionproto/scion/go/pkg/cs/drkey/grpc"
	"github.com/scionproto/scion/go/pkg/cs/drkey/test"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

func TestRequestToLvl1Req(t *testing.T) {
	now := time.Now().UTC()

	valTime, err := ptypes.TimestampProto(now)
	require.NoError(t, err)
	timestamp, err := ptypes.TimestampProto(now)
	require.NoError(t, err)

	dstIA := xtest.MustParseIA("1-ff00:0:110").IAInt()

	req := &dkpb.DRKeyLvl1Request{
		Dst_IA:    uint64(dstIA),
		ValTime:   valTime,
		Timestamp: timestamp,
	}

	lvl1Req, err := dk_grpc.RequestToLvl1Req(req)
	require.NoError(t, err)
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:110"), lvl1Req.DstIA)
	assert.Equal(t, now, lvl1Req.ValTime)
	assert.Equal(t, now, lvl1Req.Timestamp)
}

func TestKeyToLvl1Resp(t *testing.T) {
	epochBegin, err := ptypes.TimestampProto(util.SecsToTime(0))
	require.NoError(t, err)
	epochEnd, err := ptypes.TimestampProto(util.SecsToTime(1))
	require.NoError(t, err)
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	lvl1Key := drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(0, 1),
			SrcIA: srcIA,
			DstIA: dstIA,
		},
		Key: k,
	}

	targetResp := &dkpb.DRKeyLvl1Response{
		Dst_IA:     uint64(dstIA.IAInt()),
		Src_IA:     uint64(srcIA.IAInt()),
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(k),
	}

	pbResp, err := dk_grpc.KeyToLvl1Resp(lvl1Key)
	targetResp.Timestamp = pbResp.Timestamp
	require.NoError(t, err)
	assert.Equal(t, targetResp, pbResp)

}

func TestGetLvl1KeyFromReply(t *testing.T) {
	epochBegin, err := ptypes.TimestampProto(util.SecsToTime(0))
	require.NoError(t, err)
	epochEnd, err := ptypes.TimestampProto(util.SecsToTime(1))
	require.NoError(t, err)
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	resp := &dkpb.DRKeyLvl1Response{
		Dst_IA:     uint64(dstIA.IAInt()),
		Src_IA:     uint64(srcIA.IAInt()),
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(k),
	}

	targetLvl1Key := drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			Epoch: drkey.NewEpoch(0, 1),
			SrcIA: srcIA,
			DstIA: dstIA,
		},
		Key: k,
	}

	lvl1Key, err := dk_grpc.GetLvl1KeyFromReply(resp)
	require.NoError(t, err)
	assert.Equal(t, targetLvl1Key, lvl1Key)

}

func TestRequestToLvl2Req(t *testing.T) {
	now := time.Now().UTC()
	valTime, err := ptypes.TimestampProto(now)
	require.NoError(t, err)
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	reqType := drkey.Host2Host
	hostType := addr.HostTypeSVC
	hostAddr := addr.SvcCS

	req := &dkpb.DRKeyLvl2Request{
		Protocol: "piskes",
		ReqType:  uint32(reqType),
		Dst_IA:   uint64(dstIA.IAInt()),
		Src_IA:   uint64(srcIA.IAInt()),
		ValTime:  valTime,
		SrcHost: &dkpb.DRKeyLvl2Request_DRKeyHost{
			Type: uint32(hostType),
			Host: []byte(hostAddr.Pack()),
		},
		DstHost: &dkpb.DRKeyLvl2Request_DRKeyHost{
			Type: uint32(hostType),
			Host: []byte(hostAddr.Pack()),
		},
	}

	targetLvl2Req := ctrl.Lvl2Req{
		Protocol: "piskes",
		ReqType:  uint32(reqType),
		ValTime:  now,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost: ctrl.Host{
			Type: hostType,
			Host: []byte(hostAddr.Pack()),
		},
		DstHost: ctrl.Host{
			Type: hostType,
			Host: []byte(hostAddr.Pack()),
		},
	}

	lvl2Req, err := dk_grpc.RequestToLvl2Req(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)

}

func TestKeyToLvl2Resp(t *testing.T) {
	meta, lvl1Key := test.GetInputToDeriveLvl2Key(t)
	lvl2Key, err := dk_grpc.DeriveLvl2(meta, lvl1Key)
	require.NoError(t, err)

	epochBegin, err := ptypes.TimestampProto(lvl2Key.Epoch.NotBefore)
	require.NoError(t, err)
	epochEnd, err := ptypes.TimestampProto(lvl2Key.Epoch.NotAfter)
	require.NoError(t, err)

	targetResp := &dkpb.DRKeyLvl2Response{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(lvl2Key.Key),
	}

	resp, err := dk_grpc.KeyToLvl2Resp(lvl2Key)
	require.NoError(t, err)
	targetResp.Timestamp = resp.Timestamp
	assert.Equal(t, targetResp, resp)
}
