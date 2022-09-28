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

package drkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

func TestLvl1MetaToProtoRequest(t *testing.T) {
	now := time.Now().UTC()

	valTime := timestamppb.New(now)

	pbReq := &dkpb.Lvl1Request{
		ValTime: valTime,
	}

	lvl1Meta := drkey.Lvl1Meta{
		Validity: now,
	}

	req, err := drkey.Lvl1MetaToProtoRequest(lvl1Meta)
	require.NoError(t, err)
	assert.Equal(t, pbReq, req)
}

func TestKeyToLvl1Resp(t *testing.T) {
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	lvl1Key := drkey.Lvl1Key{
		Epoch: drkey.NewEpoch(0, 1),
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	copy(lvl1Key.Key[:], k)

	targetResp := &dkpb.Lvl1Response{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        []byte(k),
	}

	pbResp, err := drkey.KeyToLvl1Resp(lvl1Key)
	require.NoError(t, err)
	assert.Equal(t, targetResp, pbResp)

}

func TestGetLvl1KeyFromReply(t *testing.T) {
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	k := xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a level 1 key

	resp := &dkpb.Lvl1Response{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        []byte(k),
	}
	lvl1meta := drkey.Lvl1Meta{
		ProtoId: drkey.SCMP,
		SrcIA:   srcIA,
		DstIA:   dstIA,
	}

	targetLvl1Key := drkey.Lvl1Key{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
	}
	copy(targetLvl1Key.Key[:], k)

	lvl1Key, err := drkey.GetLvl1KeyFromReply(lvl1meta, resp)
	require.NoError(t, err)
	assert.Equal(t, targetLvl1Key, lvl1Key)

}

func TestRequestToASHostMeta(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	strAddr := "127.0.0.1"

	req := &dkpb.ASHostRequest{
		ProtocolId: dkpb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		DstIa:      uint64(dstIA),
		SrcIa:      uint64(srcIA),
		ValTime:    valTime,
		DstHost:    strAddr,
	}

	targetLvl2Req := drkey.ASHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.Generic,
			Validity: now,
			SrcIA:    srcIA,
			DstIA:    dstIA,
		},
		DstHost: strAddr,
	}

	lvl2Req, err := drkey.RequestToASHostMeta(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)
}

func TestRequestToHostASMeta(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	strAddr := "127.0.0.1"

	req := &dkpb.HostASRequest{
		ProtocolId: dkpb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		DstIa:      uint64(dstIA),
		SrcIa:      uint64(srcIA),
		ValTime:    valTime,
		SrcHost:    strAddr,
	}

	targetLvl2Req := drkey.HostASMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.Generic,
			Validity: now,
			SrcIA:    srcIA,
			DstIA:    dstIA,
		},
		SrcHost: strAddr,
	}

	lvl2Req, err := drkey.RequestToHostASMeta(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)
}

func TestRequestToHostHostMeta(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)
	dstIA := xtest.MustParseIA("1-ff00:0:110")
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	strAddr := "127.0.0.1"

	req := &dkpb.HostHostRequest{
		ProtocolId: dkpb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		DstIa:      uint64(dstIA),
		SrcIa:      uint64(srcIA),
		ValTime:    valTime,
		SrcHost:    strAddr,
		DstHost:    strAddr,
	}

	targetLvl2Req := drkey.HostHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.Generic,
			Validity: now,
			SrcIA:    srcIA,
			DstIA:    dstIA,
		},
		SrcHost: strAddr,
		DstHost: strAddr,
	}

	lvl2Req, err := drkey.RequestToHostHostMeta(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)
}

func TestKeyToASHostResp(t *testing.T) {
	srcIA := xtest.MustParseIA("1-ff00:0:1")
	dstIA := xtest.MustParseIA("1-ff00:0:2")
	key := xtest.MustParseHexString("47bfbb7d94706dc9e79825e5a837b006")
	strAddr := "127.0.0.1"

	asHostKey := drkey.ASHostKey{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		DstHost: strAddr,
	}
	copy(asHostKey.Key[:], key)

	targetResp := &dkpb.ASHostResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        asHostKey.Key[:],
	}

	resp, err := drkey.KeyToASHostResp(asHostKey)
	require.NoError(t, err)
	assert.Equal(t, targetResp, resp)
}

func TestKeyToHostASResp(t *testing.T) {
	srcIA := xtest.MustParseIA("1-ff00:0:1")
	dstIA := xtest.MustParseIA("1-ff00:0:2")
	rawKey := xtest.MustParseHexString("47bfbb7d94706dc9e79825e5a837b006")
	strAddr := "127.0.0.1"

	key := drkey.HostASKey{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		SrcHost: strAddr,
	}
	copy(key.Key[:], rawKey)

	targetResp := &dkpb.HostASResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        key.Key[:],
	}

	resp, err := drkey.KeyToHostASResp(key)
	require.NoError(t, err)
	assert.Equal(t, targetResp, resp)
}

func TestKeyToHostHostResp(t *testing.T) {
	srcIA := xtest.MustParseIA("1-ff00:0:1")
	dstIA := xtest.MustParseIA("1-ff00:0:2")
	rawKey := xtest.MustParseHexString("47bfbb7d94706dc9e79825e5a837b006")
	strAddr := "127.0.0.1"

	key := drkey.HostHostKey{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		SrcHost: strAddr,
		DstHost: strAddr,
	}
	copy(key.Key[:], rawKey)

	targetResp := &dkpb.HostHostResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        key.Key[:],
	}

	resp, err := drkey.KeyToHostHostResp(key)
	require.NoError(t, err)
	assert.Equal(t, targetResp, resp)
}

func SVMetaToProtoRequest(t *testing.T) {
	now := time.Now().UTC()
	svReq := drkey.SVMeta{
		ProtoId:  drkey.Generic,
		Validity: now,
	}
	valTime := timestamppb.New(now)
	targetProtoReq := &dkpb.SVRequest{
		ProtocolId: dkpb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		ValTime:    valTime,
	}
	protoReq, err := drkey.SVMetaToProtoRequest(svReq)
	require.NoError(t, err)
	require.Equal(t, targetProtoReq, protoReq)
}

func TestGetSVFromReply(t *testing.T) {
	k := xtest.MustParseHexString("d29d00c39398b7588c0d31a4ffc77841")
	proto := drkey.SCMP

	resp := &dkpb.SVResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}

	targetSV := drkey.SV{
		Epoch:   drkey.NewEpoch(0, 1),
		ProtoId: proto,
	}
	copy(targetSV.Key[:], k)
	sv, err := drkey.GetSVFromReply(proto, resp)
	require.NoError(t, err)
	require.Equal(t, targetSV, sv)
}

func TestSVtoProtoResp(t *testing.T) {
	k := xtest.MustParseHexString("d29d00c39398b7588c0d31a4ffc77841")

	sv := drkey.SV{
		Epoch:   drkey.NewEpoch(0, 1),
		ProtoId: drkey.SCMP,
	}
	copy(sv.Key[:], k)

	targetResp := &dkpb.SVResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}

	resp, err := drkey.SVtoProtoResp(sv)
	require.NoError(t, err)
	require.Equal(t, targetResp, resp)
}
