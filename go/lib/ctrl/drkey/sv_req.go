// Copyright 2021 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

// SVMetaToProtoRequest parses the SVReq to a protobuf SVRequest.
func SVMetaToProtoRequest(meta drkey.SVMeta) (*dkpb.SVRequest, error) {
	valTime, err := ptypes.TimestampProto(meta.Validity)
	if err != nil {
		return nil, serrors.WrapStr("invalid valTime from request", err)
	}
	return &dkpb.SVRequest{
		ValTime:    valTime,
		ProtocolId: dkpb.Protocol(meta.ProtoId),
	}, nil
}

// SVRequestToMeta parses the SVReq to a protobuf SVRequest.
func SVRequestToMeta(req *dkpb.SVRequest) (drkey.SVMeta, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return drkey.SVMeta{}, serrors.WrapStr("invalid valTime from request", err)
	}
	return drkey.SVMeta{
		Validity: valTime,
		ProtoId:  drkey.Protocol(req.ProtocolId),
	}, nil
}

// GetSVFromReply extracts the SV from the reply.
func GetSVFromReply(proto drkey.Protocol, rep *dkpb.SVResponse) (drkey.SV, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.SV{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}
	returningKey := drkey.SV{
		ProtoId: proto,
		Epoch:   epoch,
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

// SVtoProtoResp builds a SVResponse provided a SV.
func SVtoProtoResp(drkey drkey.SV) (*dkpb.SVResponse, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochBegin from key", err)
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, serrors.WrapStr("invalid EpochEnd from key", err)
	}
	return &dkpb.SVResponse{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Key:        drkey.Key[:],
	}, nil
}
