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
	"github.com/golang/protobuf/ptypes"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

func ASHostMetaToProtoRequest(meta drkey.ASHostMeta) (*dkpb.ASHostRequest, error) {
	valTime, err := ptypes.TimestampProto(meta.Validity)
	if err != nil {
		return nil, serrors.WrapStr("invalid valTime from request", err)
	}
	return &dkpb.ASHostRequest{
		ValTime:    valTime,
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		DstHost:    meta.DstHost,
	}, nil
}

func RequestToASHostMeta(req *dkpb.ASHostRequest) (drkey.ASHostMeta, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return drkey.ASHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.ASHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.Protocol(req.ProtocolId),
			Validity: valTime,
			SrcIA:    addr.IA(req.SrcIa),
			DstIA:    addr.IA(req.DstIa),
		},
		DstHost: req.DstHost,
	}, nil
}

func KeyToASHostResp(drkey drkey.ASHostKey) (*dkpb.ASHostResponse, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochBegin from key", err)
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochEnd from key", err)
	}
	return &dkpb.ASHostResponse{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Key:        drkey.Key[:],
	}, nil
}

func GetASHostKeyFromReply(rep *dkpb.ASHostResponse,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}

	returningKey := drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		DstHost: meta.DstHost,
	}

	if len(rep.Key) != 16 {
		return drkey.ASHostKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func HostASMetaToProtoRequest(meta drkey.HostASMeta) (*dkpb.HostASRequest, error) {
	valTime, err := ptypes.TimestampProto(meta.Validity)
	if err != nil {
		return nil, serrors.WrapStr("invalid valTime from request", err)
	}
	return &dkpb.HostASRequest{
		ValTime:    valTime,
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		SrcHost:    meta.SrcHost,
	}, nil
}

func RequestToHostASMeta(req *dkpb.HostASRequest) (drkey.HostASMeta, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return drkey.HostASMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostASMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.Protocol(req.ProtocolId),
			Validity: valTime,
			SrcIA:    addr.IA(req.SrcIa),
			DstIA:    addr.IA(req.DstIa),
		},
		SrcHost: req.SrcHost,
	}, nil
}

func KeyToHostASResp(drkey drkey.HostASKey) (*dkpb.HostASResponse, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochBegin from key", err)
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochEnd from key", err)
	}
	return &dkpb.HostASResponse{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Key:        drkey.Key[:],
	}, nil
}

func GetHostASKeyFromReply(rep *dkpb.HostASResponse,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}

	returningKey := drkey.HostASKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		SrcHost: meta.SrcHost,
	}
	if len(rep.Key) != 16 {
		return drkey.HostASKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func HostHostMetaToProtoRequest(meta drkey.HostHostMeta) (*dkpb.HostHostRequest, error) {
	valTime, err := ptypes.TimestampProto(meta.Validity)
	if err != nil {
		return nil, serrors.WrapStr("invalid valTime from request", err)
	}
	return &dkpb.HostHostRequest{
		ValTime:    valTime,
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		DstHost:    meta.DstHost,
		SrcHost:    meta.SrcHost,
	}, nil
}

func RequestToHostHostMeta(req *dkpb.HostHostRequest) (drkey.HostHostMeta, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return drkey.HostHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostHostMeta{
		Lvl2Meta: drkey.Lvl2Meta{
			ProtoId:  drkey.Protocol(req.ProtocolId),
			Validity: valTime,
			SrcIA:    addr.IA(req.SrcIa),
			DstIA:    addr.IA(req.DstIa),
		},
		SrcHost: req.SrcHost,
		DstHost: req.DstHost,
	}, nil
}

func KeyToHostHostResp(drkey drkey.HostHostKey) (*dkpb.HostHostResponse, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochBegin from key", err)
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochEnd from key", err)
	}
	return &dkpb.HostHostResponse{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Key:        drkey.Key[:],
	}, nil
}

func GetHostHostKeyFromReply(rep *dkpb.HostHostResponse,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}

	returningKey := drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
	}
	if len(rep.Key) != 16 {
		return drkey.HostHostKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
