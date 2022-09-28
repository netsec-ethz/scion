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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

// SVMetaToProtoRequest parses the SVReq to a protobuf SVRequest.
func SVMetaToProtoRequest(meta SVMeta) (*dkpb.SVRequest, error) {
	return &dkpb.SVRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
	}, nil
}

// SVRequestToMeta parses the SVReq to a protobuf SVRequest.
func SVRequestToMeta(req *dkpb.SVRequest) (SVMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return SVMeta{}, serrors.WrapStr("invalid valTime from request", err)
	}
	return SVMeta{
		Validity: req.ValTime.AsTime(),
		ProtoId:  Protocol(req.ProtocolId),
	}, nil
}

// GetSVFromReply extracts the SV from the reply.
func GetSVFromReply(proto Protocol, rep *dkpb.SVResponse) (SV, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return SV{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return SV{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := SV{
		ProtoId: proto,
		Epoch:   epoch,
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

// SVtoProtoResp builds a SVResponse provided a SV.
func SVtoProtoResp(drkey SV) (*dkpb.SVResponse, error) {
	return &dkpb.SVResponse{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}, nil
}
