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

// Host represents a host part of a level 2 drkey.
type Host struct {
	Type addr.HostAddrType // uint8
	Host []byte
}

// NewHost returns a new Host from an addr.HostAddr.
func NewHost(host addr.HostAddr) Host {
	if host == nil {
		host = addr.HostNone{}
	}
	return Host{
		Type: host.Type(),
		Host: host.Pack(),
	}
}

// ToHostAddr returns the host as a addr.HostAddr.
func (h *Host) ToHostAddr() addr.HostAddr {
	host, err := addr.HostFromRaw(h.Host, addr.HostAddrType(h.Type))
	if err != nil {
		panic("Could not convert addr.HostAddr to drkey.Host")
	}
	return host
}

// Lvl2Req represents a level 2 key request from an endhost to a CS.
type Lvl2Req struct {
	Protocol string
	ReqType  uint32
	ValTime  time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  Host
	DstHost  Host
	Misc     []byte
}

// NewLvl2ReqFromMeta constructs a level 2 request from a standard level 2 meta info.
func NewLvl2ReqFromMeta(meta drkey.Lvl2Meta, valTime time.Time) Lvl2Req {
	return Lvl2Req{
		ReqType:  uint32(meta.KeyType),
		Protocol: meta.Protocol,
		ValTime:  valTime,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
		SrcHost:  NewHost(meta.SrcHost),
		DstHost:  NewHost(meta.DstHost),
	}
}

// ToMeta returns metadata of the requested Lvl2 DRKey.
func (c Lvl2Req) ToMeta() drkey.Lvl2Meta {
	return drkey.Lvl2Meta{
		KeyType:  drkey.Lvl2KeyType(c.ReqType),
		Protocol: c.Protocol,
		SrcIA:    c.SrcIA,
		DstIA:    c.DstIA,
		SrcHost:  c.SrcHost.ToHostAddr(),
		DstHost:  c.DstHost.ToHostAddr(),
	}
}

// RequestToLvl2Req parses the protobuf Lvl2Request to a Lvl2Req.
func RequestToLvl2Req(req *dkpb.DRKeyLvl2Request) (Lvl2Req, error) {
	valTime, err := ptypes.Timestamp(req.ValTime)
	if err != nil {
		return Lvl2Req{}, err
	}

	return Lvl2Req{
		Protocol: req.Protocol,
		ReqType:  req.ReqType,
		ValTime:  valTime,
		SrcIA:    addr.IAInt(req.SrcIa).IA(),
		DstIA:    addr.IAInt(req.DstIa).IA(),
		SrcHost: Host{
			Type: addr.HostAddrType(req.SrcHost.Type),
			Host: req.SrcHost.Host,
		},
		DstHost: Host{
			Type: addr.HostAddrType(req.DstHost.Type),
			Host: req.DstHost.Host,
		},
		Misc: req.Misc,
	}, nil
}

// KeyToLvl2Resp builds a Lvl2Resp provided a given Lvl2Key.
func KeyToLvl2Resp(drkey drkey.Lvl2Key) (*dkpb.DRKeyLvl2Response, error) {
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

	return &dkpb.DRKeyLvl2Response{
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
		Drkey:      []byte(drkey.Key),
		Timestamp:  now,
	}, nil
}

// Lvl2reqToProtoRequest parses the Lvl2Req to a protobuf Lvl2Request.
func Lvl2reqToProtoRequest(req Lvl2Req) (*dkpb.DRKeyLvl2Request, error) {
	valTime, err := ptypes.TimestampProto(req.ValTime)
	if err != nil {
		return nil, err
	}
	return &dkpb.DRKeyLvl2Request{
		Protocol: req.Protocol,
		ReqType:  req.ReqType,
		DstIa:    uint64(req.DstIA.IAInt()),
		SrcIa:    uint64(req.DstIA.IAInt()),
		ValTime:  valTime,
		SrcHost: &dkpb.DRKeyLvl2Request_DRKeyHost{
			Type: uint32(req.SrcHost.Type),
			Host: req.SrcHost.Host,
		},
		DstHost: &dkpb.DRKeyLvl2Request_DRKeyHost{
			Type: uint32(req.DstHost.Type),
			Host: req.DstHost.Host,
		},
	}, nil
}

// GetLvl2KeyFromReply extracts the level 2 drkey from the reply.
func GetLvl2KeyFromReply(rep *dkpb.DRKeyLvl2Response, meta drkey.Lvl2Meta) (drkey.Lvl2Key, error) {

	epochBegin, err := ptypes.Timestamp(rep.EpochBegin)
	if err != nil {
		return drkey.Lvl2Key{}, err
	}
	epochEnd, err := ptypes.Timestamp(rep.EpochEnd)
	if err != nil {
		return drkey.Lvl2Key{}, err
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochBegin,
			NotAfter:  epochEnd,
		},
	}
	return drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  meta.KeyType,
			Protocol: meta.Protocol,
			SrcIA:    meta.SrcIA,
			DstIA:    meta.DstIA,
			SrcHost:  meta.SrcHost,
			DstHost:  meta.DstHost,
			Epoch:    epoch,
		},
		Key: drkey.DRKey(rep.Drkey),
	}, nil
}
