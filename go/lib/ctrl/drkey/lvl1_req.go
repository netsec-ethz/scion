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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

func Lvl1MetaToProtoRequest(meta drkey.Lvl1Meta) (*dkpb.Lvl1Request, error) {
	return &dkpb.Lvl1Request{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
	}, nil
}

// GetLvl1KeyFromReply extracts the level 1 drkey from the reply.
func GetLvl1KeyFromReply(meta drkey.Lvl1Meta,
	rep *dkpb.Lvl1Response) (drkey.Lvl1Key, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.Lvl1Key{
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		ProtoId: meta.ProtoId,
	}
	if len(rep.Key) != 16 {
		return drkey.Lvl1Key{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

// KeyToLvl1Resp builds a Lvl1Resp provided a Lvl1Key.
func KeyToLvl1Resp(drkey drkey.Lvl1Key) (*dkpb.Lvl1Response, error) {
	return &dkpb.Lvl1Response{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}, nil
}

func IntraLvl1ToProtoRequest(meta drkey.Lvl1Meta) (*dkpb.IntraLvl1Request, error) {
	return &dkpb.IntraLvl1Request{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
	}, nil
}

// KeyToASASResp builds a ASASResp provided a Lvl1Key.
func KeyToASASResp(drkey drkey.Lvl1Key) (*dkpb.IntraLvl1Response, error) {
	return &dkpb.IntraLvl1Response{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}, nil
}

func GetASASKeyFromReply(meta drkey.Lvl1Meta,
	rep *dkpb.IntraLvl1Response) (drkey.Lvl1Key, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.Lvl1Key{
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		ProtoId: meta.ProtoId,
	}
	if len(rep.Key) != 16 {
		return drkey.Lvl1Key{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
