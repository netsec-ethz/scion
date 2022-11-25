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

package router

import (
	"encoding/binary"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/addr"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

type colibriPacketProcessor struct {
	// d is a reference to the dataplane instance that initiated this processor.
	d *DataPlane
	// ingressID is the interface ID this packet came in, determined from the
	// socket.
	ingressID uint16
	// rawPkt is the raw packet, it is updated during processing to contain the
	// message to send out.
	rawPkt []byte
	// scionLayer is the SCION gopacket layer (common/address header).
	scionLayer slayers.SCION
	// buffer is the buffer that can be used to serialize gopacket layers.
	buffer gopacket.SerializeBuffer

	// colibriPathMinimal is the optimized representation of the colibri path type.
	colibriPathMinimal *colibri.ColibriPathMinimal
}

func (c *colibriPacketProcessor) process() (processResult, error) {
	if c == nil {
		return processResult{}, serrors.New("colibri packet processor must not be nil")
	}

	// Get path
	if r, err := c.getPath(); err != nil {
		return r, err
	}
	// Basic validation checks
	if r, err := c.basicValidation(); err != nil {
		return r, err
	}
	// Check hop field MAC
	if r, err := c.cryptographicValidation(); err != nil {
		return r, err
	}
	// TODO(juagargi) add SCMP errors for bad packets, ingress and egress down, etc.
	// Forward the packet to the correct entity
	return c.forward()
}

func (c *colibriPacketProcessor) getPath() (processResult, error) {
	var ok bool
	c.colibriPathMinimal, ok = c.scionLayer.Path.(*colibri.ColibriPathMinimal)
	if !ok {
		return processResult{}, serrors.New("getting minimal colibri path information failed")
	}
	return processResult{}, nil

}

func (c *colibriPacketProcessor) basicValidation() (processResult, error) {
	R := c.colibriPathMinimal.InfoField.R
	S := c.colibriPathMinimal.InfoField.S
	C := c.colibriPathMinimal.InfoField.C

	// Consistency of flags: S implies C
	if S && !C {
		return processResult{}, serrors.New("invalid flags", "S", S, "R", R, "C", C)
	}
	// Correct ingress interface (if we received the packet on the local interface, we do not
	// need to check the interface in the hop field)
	if c.ingressID != 0 && c.ingressID != c.colibriPathMinimal.CurrHopField.IngressId {
		return processResult{}, serrors.New("invalid ingress identifier",
			"receivedOn", c.ingressID,
			"HopFieldIngressId", c.colibriPathMinimal.CurrHopField.IngressId)
	}
	// Valid packet length
	if (!R && c.scionLayer.PayloadLen != c.colibriPathMinimal.InfoField.OrigPayLen) ||
		(int(c.scionLayer.PayloadLen) != len(c.scionLayer.Payload)) {

		return processResult{}, serrors.New("packet length validation failed",
			"scion", c.scionLayer.PayloadLen, "colibri", c.colibriPathMinimal.InfoField.OrigPayLen,
			"actual", len(c.scionLayer.Payload))
	}
	// Colibri path has at least two hop fields
	hfCount := c.colibriPathMinimal.InfoField.HFCount
	currHF := c.colibriPathMinimal.InfoField.CurrHF
	if hfCount < 2 {
		return processResult{}, serrors.New("colibri path needs to have at least 2 hop fields",
			"has", hfCount)
	}
	// Valid current hop field index
	if currHF >= hfCount {
		return processResult{}, serrors.New("invalid current hop field index",
			"currHF", currHF, "hfCount", hfCount)
	}

	// Reservation not expired
	expTick := c.colibriPathMinimal.InfoField.ExpTick
	notExpired := libcolibri.VerifyExpirationTick(expTick)
	if !notExpired {
		return processResult{}, serrors.New("packet expired")
	}

	// Packet freshness
	if !C {
		timestamp := c.colibriPathMinimal.PacketTimestamp
		isFresh := libcolibri.VerifyTimestamp(expTick, timestamp, time.Now())
		if !isFresh {
			return processResult{}, serrors.New("verification of packet timestamp failed")
		}
	}

	// Check if destined to local AS: egress is 0, dst is local, no more hosts must be equal
	isLocal := c.colibriPathMinimal.CurrHopField.EgressId == 0
	if (isLocal != c.colibriPathMinimal.IsLastHop()) ||
		(isLocal != c.scionLayer.DstIA.Equal(c.d.localIA)) {

		return processResult{}, serrors.New("inconsistent packet",
			"egress_id", c.colibriPathMinimal.CurrHopField.EgressId,
			"is_last_hop", c.colibriPathMinimal.IsLastHop(),
			"dst", c.scionLayer.DstIA,
			"(local)", c.d.localIA)
	}
	return processResult{}, nil
}

func (c *colibriPacketProcessor) cryptographicValidation() (processResult, error) {
	privateKey := c.d.colibriKey
	colHeader := c.colibriPathMinimal
	err := libcolibri.VerifyMAC(privateKey, colHeader.PacketTimestamp, colHeader.InfoField,
		colHeader.CurrHopField, &c.scionLayer)
	return processResult{}, err
}

func (c *colibriPacketProcessor) forward() (processResult, error) {
	egressId := c.colibriPathMinimal.CurrHopField.EgressId

	if c.ingressID == 0 {
		// Received packet from within AS
		if conn, ok := c.canForwardLocally(egressId); ok {
			return c.forwardToLocalEgress(egressId, conn)
		}
		return processResult{}, serrors.New("received packet from local AS but the packet should " +
			"go to different border router")
	}

	// Received packet from outside of the AS
	if c.colibriPathMinimal.InfoField.C {
		// Control plane forwarding
		// Assumption: in case there are multiple COLIBRI services, they are always synchronized,
		// so we can forward the packet to an arbitrary COLIBRI service.
		return c.forwardToColibriSvc()
	} else {
		// Data plane forwarding
		if egressId == 0 {
			return c.forwardToLocalAS()
		} else {
			if conn, ok := c.canForwardLocally(egressId); ok {
				return c.forwardToLocalEgress(egressId, conn)
			}
			return c.forwardToRemoteEgress(egressId)
		}
	}
}

func (c *colibriPacketProcessor) canForwardLocally(egressId uint16) (BatchConn, bool) {
	conn, ok := c.d.external[egressId]
	return conn, ok
}

func (c *colibriPacketProcessor) forwardToLocalEgress(egressId uint16,
	conn BatchConn) (processResult, error) {
	// BR transit: the packet will leave the AS through the same border router, but through a
	// different interface.

	// Increase the hop field index.
	if err := c.colibriPathMinimal.UpdateCurrHF(); err != nil {
		return processResult{}, err
	}
	// Serialize updated hop field index into rawPkt.
	if err := c.colibriPathMinimal.SerializeToInternal(); err != nil {
		return processResult{}, err
	}
	return processResult{EgressID: egressId, OutConn: conn, OutPkt: c.rawPkt}, nil
}

func (c *colibriPacketProcessor) forwardToRemoteEgress(egressId uint16) (processResult, error) {
	// AS transit: the packet will leave the AS from another border router.
	if a, ok := c.d.internalNextHops[egressId]; ok {
		return processResult{OutConn: c.d.internal, OutAddr: a, OutPkt: c.rawPkt}, nil
	} else {
		return processResult{}, serrors.New("no remote border router with this egress id",
			"egressId", egressId)
	}
}

func (c *colibriPacketProcessor) forwardToLocalAS() (processResult, error) {
	// Inbound: packet destined to a host in the local IA.
	a, err := c.d.resolveLocalDst(c.scionLayer)
	if err != nil {
		return processResult{}, err
	}
	return processResult{OutConn: c.d.internal, OutAddr: a, OutPkt: c.rawPkt}, nil
}

func (c *colibriPacketProcessor) forwardToColibriSvc() (processResult, error) {
	// Inbound: packet destined to the local colibri service.

	// Get address of colibri service (pick one at random if there are multiple COLIBRI services)
	// Assumption: in case there are multiple COLIBRI services, they are always synchronized
	a, ok := c.d.svc.Any(addr.SvcCOL.Base())
	if !ok {
		return processResult{}, serrors.New("no colibri service registered at border router")
	}

	// XXX(mawyss): This is a temporary solution to allow the dispatcher to forward Colibri
	// control packets to the right destination (https://github.com/netsec-ethz/scion/pull/116).
	// Encode the current ISD/AS in the Colibri high-precision timestamp field of control
	// packets (C=1). This serves the purpose of supporting one single dispatcher for multiple
	// ASes, as now the dispatcher can know to which AS the Colibri control packet should be
	// forwarded.
	binary.BigEndian.PutUint64(c.colibriPathMinimal.PacketTimestamp[:], uint64(c.d.localIA))
	if err := c.colibriPathMinimal.SerializeToInternal(); err != nil {
		return processResult{}, err
	}

	return processResult{OutConn: c.d.internal, OutAddr: a, OutPkt: c.rawPkt}, nil
}
