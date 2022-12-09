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

package colibri

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	caddr "github.com/scionproto/scion/go/lib/slayers/path/colibri/addr"
	"github.com/scionproto/scion/go/lib/slayers/scion"
)

type ColibriPathFacade interface {
	GetInfoField() *InfoField
	GetCurrentHopField() *HopField
}

type Timestamp [8]byte

type ColibriPath struct {
	// PacketTimestamp denotes the high-precision timestamp.
	PacketTimestamp Timestamp
	// InfoField denotes the COLIBRI info field.
	InfoField *InfoField
	// HopFields denote the COLIBRI hop fields.
	HopFields []*HopField
	// Source address taken  from the SCION layer
	Src *caddr.Endpoint
	// Destination address taken  from the SCION layer
	Dst *caddr.Endpoint
}

func (c *ColibriPath) String() string {
	if c == nil {
		return "(nil)"
	}
	var as addr.AS
	if c.Src != nil {
		as = c.Src.IA.AS()
	}
	ID := reservation.ID{
		ASID:   as,
		Suffix: c.InfoField.ResIdSuffix,
	}
	inf := c.InfoField
	return fmt.Sprintf("%s -> %s [ID: %s,Idx: %d] (#HFs:%d,CurrHF:%d,S:%v C:%v R:%v)",
		c.Src, c.Dst, ID, inf.Ver, inf.HFCount, inf.CurrHF, inf.S, inf.C, inf.R)
}

func (c *ColibriPath) GetInfoField() *InfoField {
	return c.InfoField
}

func (c *ColibriPath) GetCurrentHopField() *HopField {
	return c.HopFields[c.InfoField.CurrHF]
}

func (c *ColibriPath) SerializeTo(b []byte) error {
	if c == nil {
		return serrors.New("colibri path must not be nil")
	}
	if c.InfoField == nil {
		return serrors.New("the info field must not be nil")
	}
	if len(b) < c.Len() {
		return serrors.New("buffer for ColibriPath too short", "is:", len(b),
			"needs:", c.Len())
	}

	copy(b[:8], c.PacketTimestamp[:])
	if err := c.InfoField.SerializeTo(b[8 : 8+LenInfoField]); err != nil {
		return err
	}
	for i, hf := range c.HopFields {
		start := 8 + LenInfoField + i*LenHopField
		end := start + LenHopField
		if err := hf.SerializeTo(b[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c *ColibriPath) SyncWithScionHeader(scion *scion.Header) error {
	log.Debug("deleteme colibri path sync",
		"path", c.String(),
	)

	if !c.InfoField.R && !c.InfoField.C {
		// Update the size for the replier to use it in the MAC verification (EER non reply only).
		// Use the actual size right before putting the packet in the wire.
		c.InfoField.OrigPayLen = scion.PayloadLen
	}

	// Update the SCION layer fields (SRC and DST) that must be affected by this colibri path.
	if c.Src == nil { // deleteme
		panic("src is nil")
	}
	if c.Dst == nil { // deleteme
		panic("src is nil")
	}

	scion.SrcIA = c.Src.IA
	// TODO(juagargi) a problem in the dispatcher prevents the ACK packets from being dispatched
	// correctly. For now, we need to keep the IP address of the original sender, which is
	// each one of the colibri services that contact the next colibri service.
	// The problem: when the ACK packet is created and sent, if the destination address is
	// a service, the dispatcher on the receiver of the ACK side won't be able to find the correct
	// socket (the client one), as it is registered as a no service. It will instead dispatch
	// the packet to the colibri service listener, which is not expecting this ACK.
	// For now we just send the packets with the individual address, to allow the ACK to come back.
	// scion.RawSrcAddr, scion.SrcAddrType, scion.SrcAddrLen = c.Src.HostAsRaw()

	scion.DstIA = c.Dst.IA
	scion.RawDstAddr, scion.DstAddrType, scion.DstAddrLen = c.Dst.HostAsRaw()

	return nil
}

func (c *ColibriPath) DecodeFromBytes(b []byte) error {
	if c == nil {
		return serrors.New("colibri path must not be nil")
	}
	if len(b) < LenMinColibri {
		return serrors.New("raw colibri path too short", "is:", len(b),
			"needs:", LenMinColibri)
	}

	copy(c.PacketTimestamp[:], b[:8])
	if c.InfoField == nil {
		c.InfoField = &InfoField{}
	}
	if err := c.InfoField.DecodeFromBytes(b[8 : 8+LenInfoField]); err != nil {
		return err
	}
	nrHopFields := int(c.InfoField.HFCount)
	if 8+LenInfoField+(nrHopFields*LenHopField) > len(b) {
		return serrors.New("raw colibri path is smaller than what is " +
			"indicated by HFCount in the info field")
	}
	c.HopFields = make([]*HopField, nrHopFields)
	for i := 0; i < nrHopFields; i++ {
		start := 8 + LenInfoField + i*LenHopField
		end := start + LenHopField
		c.HopFields[i] = &HopField{}
		if err := c.HopFields[i].DecodeFromBytes(b[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (cp *ColibriPath) BuildFromHeader(b []byte, sc *scion.Header) error {
	cp.Src = caddr.NewEndpointWithRaw(sc.SrcIA, sc.RawSrcAddr, sc.SrcAddrType, sc.SrcAddrLen)
	cp.Dst = caddr.NewEndpointWithRaw(sc.DstIA, sc.RawDstAddr, sc.DstAddrType, sc.DstAddrLen)
	return cp.DecodeFromBytes(b)
}

// Reverse the path: toggle the R-flag, invert the order of the hop fields, and adapt the CurrHF.
func (c *ColibriPath) Reverse() (path.Path, error) {
	// TODO(juagargi) many checks in regular processing. Validate path at beginning and remove these
	if c == nil {
		return nil, serrors.New("colibri path must not be nil")
	}
	if c.InfoField == nil {
		return nil, serrors.New("the info field must not be nil")
	}
	if c.InfoField.CurrHF >= c.InfoField.HFCount {
		return nil, serrors.New("CurrHF >= HFCount", "CurrHF", c.InfoField.CurrHF,
			"HFCount", c.InfoField.HFCount)
	}

	c.InfoField.R = !c.InfoField.R
	c.InfoField.CurrHF = c.InfoField.HFCount - c.InfoField.CurrHF - 1

	hf := len(c.HopFields)
	for i := 0; i < hf/2; i++ {
		// reverse hop fields in the array by swapping left with right
		c.HopFields[i], c.HopFields[hf-i-1] = c.HopFields[hf-i-1], c.HopFields[i]
		// swap ingress with egress
		c.HopFields[i].SwapInEg()
		c.HopFields[hf-i-1].SwapInEg()
	}
	if hf%2 == 1 {
		// no need to reverse in the array, but do the swap
		c.HopFields[hf/2].SwapInEg()
	}

	c.Src, c.Dst = c.Dst, c.Src

	return c, nil
}

func (c *ColibriPath) Len() int {
	if c == nil {
		return 0
	}
	return 8 + LenInfoField + len(c.HopFields)*LenHopField
}

func (c *ColibriPath) Type() path.Type {
	return PathType
}

func (c *ColibriPath) ToMinimal() (*ColibriPathMinimal, error) {
	min := &ColibriPathMinimal{
		PacketTimestamp: c.PacketTimestamp,
		InfoField:       c.InfoField.Clone(),
		CurrHopField:    c.GetCurrentHopField().Clone(),
		Raw:             make([]byte, c.Len()),
		Src:             c.Src,
		Dst:             c.Dst,
	}
	err := c.SerializeTo(min.Raw)
	return min, err
}

func (c *ColibriPath) Clone() *ColibriPath {
	p := &ColibriPath{
		PacketTimestamp: c.PacketTimestamp,
		InfoField:       c.InfoField.Clone(),
		HopFields:       make([]*HopField, len(c.HopFields)),
	}
	for i, hf := range c.HopFields {
		p.HopFields[i] = hf.Clone()
	}
	return p
}
