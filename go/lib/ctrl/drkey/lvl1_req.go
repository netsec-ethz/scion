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
	"time"

	"github.com/golang/protobuf/ptypes"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

// Lvl1Req represents a level 1 request between CS.
type Lvl1Req struct {
	DstIA     addr.IA
	ValTime   time.Time
	Timestamp time.Time
}

// NewLvl1Req returns a fresh Lvl1Req
func NewLvl1Req(dstIA addr.IA, valTime time.Time) Lvl1Req {
	return Lvl1Req{
		DstIA:     dstIA,
		ValTime:   valTime,
		Timestamp: time.Now(),
	}
}

// Lvl1reqToProtoRequest parses the Lvl1Req to a protobuf Lvl1Request.
func Lvl1reqToProtoRequest(req Lvl1Req) (*dkpb.DRKeyLvl1Request, error) {
	valTime, err := ptypes.TimestampProto(req.ValTime)
	if err != nil {
		return nil, err
	}
	timestamp, err := ptypes.TimestampProto(req.Timestamp)
	if err != nil {
		return nil, err
	}
	return &dkpb.DRKeyLvl1Request{
		DstIa:     uint64(req.DstIA.IAInt()),
		ValTime:   valTime,
		Timestamp: timestamp,
	}, nil
}

// GetLvl1KeyFromReply extracts the level 1 drkey from the reply.
func GetLvl1KeyFromReply(rep *dkpb.DRKeyLvl1Response) (drkey.Lvl1Key, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}
	return drkey.Lvl1Key{
		Lvl1Meta: drkey.Lvl1Meta{
			SrcIA: addr.IAInt(rep.SrcIa).IA(),
			DstIA: addr.IAInt(rep.DstIa).IA(),
			Epoch: epoch,
		},
		Key: drkey.DRKey(rep.Drkey),
	}, nil
}

// KeyToLvl1Resp builds a Lvl1Resp provided a given Lvl1Key.
func KeyToLvl1Resp(drkey drkey.Lvl1Key) (*dkpb.DRKeyLvl1Response, error) {
	epochBegin, err := ptypes.TimestampProto(drkey.Epoch.NotBefore)
	if err != nil {
		return nil, err
	}
	epochEnd, err := ptypes.TimestampProto(drkey.Epoch.NotAfter)
	if err != nil {
		return nil, err
	}
	now, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		return nil, err
	}

	return &dkpb.DRKeyLvl1Response{
		DstIa:      uint64(drkey.DstIA.IAInt()),
		SrcIa:      uint64(drkey.SrcIA.IAInt()),
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(drkey.Key),
		Timestamp:  now,
	}, nil
}

// RequestToLvl1Req parses the protobuf Lvl1Request to a Lvl1Req.
func RequestToLvl1Req(req *dkpb.DRKeyLvl1Request) (Lvl1Req, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return Lvl1Req{}, err
	}
	timestamp, err := ptypes.Timestamp(req.Timestamp)
	if err != nil {
		return Lvl1Req{}, err
	}

	return Lvl1Req{
		DstIA:     addr.IAInt(req.DstIa).IA(),
		ValTime:   valTime,
		Timestamp: timestamp,
	}, nil
}
