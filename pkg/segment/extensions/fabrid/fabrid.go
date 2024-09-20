// Copyright 2024 ETH Zurich
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

package fabrid

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	fabridpb "github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	"github.com/scionproto/scion/pkg/segment/extensions/digest"
)

type SupportedIndicesMap map[ConnectionPair][]uint8

type IndexIdentifierMap map[uint8]*PolicyIdentifier

type Detached struct {
	SupportedIndicesMap SupportedIndicesMap
	IndexIdentiferMap   IndexIdentifierMap
}

func (ind *SupportedIndicesMap) SortedKeys() []ConnectionPair {
	orderedKeysSupIndex := make([]ConnectionPair, 0, len(*ind))
	for k := range *ind {
		orderedKeysSupIndex = append(orderedKeysSupIndex, k)
	}
	sort.Slice(orderedKeysSupIndex, func(i int, j int) bool {
		if orderedKeysSupIndex[i].Ingress != orderedKeysSupIndex[j].Ingress {
			return orderedKeysSupIndex[i].Ingress.Less(orderedKeysSupIndex[j].Ingress)
		}
		return orderedKeysSupIndex[i].Egress.Less(orderedKeysSupIndex[j].Egress)
	})
	return orderedKeysSupIndex
}

func (id *IndexIdentifierMap) SortedKeys() []uint8 {
	orderedKeys := make([]uint8, 0, len(*id))
	for k := range *id {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Slice(orderedKeys, func(i int, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	})
	return orderedKeys
}

type ConnectionPointType string

const (
	IPv4Range ConnectionPointType = "ipv4"
	IPv6Range ConnectionPointType = "ipv6"
	Interface ConnectionPointType = "interface"
	Wildcard  ConnectionPointType = "wildcard"
)

type ConnectionPoint struct {
	Type        ConnectionPointType
	IP          string // Stored as a string to allow it to be key of a map.
	Prefix      uint32
	InterfaceId uint16
}

// IPConnectionPointFromString parses a string IP address and Prefix, then masks the IP with the
// prefix and returns a ConnectionPoint with the parsed IP, type and prefix.
func IPConnectionPointFromString(IP string, Prefix uint32,
	Type ConnectionPointType) ConnectionPoint {
	var m net.IPMask
	if Type == IPv4Range {
		m = net.CIDRMask(int(Prefix), 8*net.IPv4len)
	} else if Type == IPv6Range {
		m = net.CIDRMask(int(Prefix), 8*net.IPv6len)
	}
	return ConnectionPoint{Type: Type, IP: net.ParseIP(IP).Mask(m).String(), Prefix: Prefix}
}

func (c *ConnectionPoint) Less(d ConnectionPoint) bool {
	if c.Type != d.Type {
		return c.Type < d.Type
	}
	if c.IP != d.IP {
		return c.IP < d.IP
	}
	if c.Prefix != d.Prefix {
		return c.Prefix < d.Prefix
	}
	return c.InterfaceId < d.InterfaceId
}

func (c *ConnectionPoint) IPNetwork() *net.IPNet {
	if c.Type == IPv4Range {
		m := net.CIDRMask(int(c.Prefix), 8*net.IPv4len)
		return &net.IPNet{IP: net.ParseIP(c.IP).Mask(m), Mask: m}
	} else if c.Type == IPv6Range {
		m := net.CIDRMask(int(c.Prefix), 8*net.IPv6len)
		return &net.IPNet{IP: net.ParseIP(c.IP).Mask(m), Mask: m}
	}
	return &net.IPNet{}
}
func (c *ConnectionPoint) MatchesIF(intf uint16) bool {
	return (c.Type == Interface && c.InterfaceId == intf) || c.Type == Wildcard
}

type ConnectionPair struct {
	Ingress ConnectionPoint
	Egress  ConnectionPoint
}

func (c *ConnectionPair) Matches(ingress, egress uint16, allowIpPolicies bool) bool {
	match := c.Ingress.MatchesIF(ingress) && c.Egress.MatchesIF(egress)
	if allowIpPolicies {
		match = match || (c.Ingress.MatchesIF(ingress) && egress == 0 &&
			(c.Egress.Type == IPv4Range || c.Egress.Type == IPv6Range))
	}
	return match
}

type PolicyIdentifier struct {
	IsLocal    bool
	Identifier uint32
}

func PolicyIdentifierToPB(identifier *PolicyIdentifier) *fabridpb.FABRIDPolicyIdentifier {
	return &fabridpb.FABRIDPolicyIdentifier{
		PolicyIsLocal:    identifier.IsLocal,
		PolicyIdentifier: identifier.Identifier,
	}
}

func PolicyIdentifierFromPB(identifier *fabridpb.FABRIDPolicyIdentifier) *PolicyIdentifier {
	return &PolicyIdentifier{
		IsLocal:    identifier.PolicyIsLocal,
		Identifier: identifier.PolicyIdentifier,
	}
}

func ConnectionPointToPB(point ConnectionPoint) *fabridpb.FABRIDConnectionPoint {
	switch point.Type {
	case IPv4Range:
		return &fabridpb.FABRIDConnectionPoint{
			Type:      fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_IPV4_RANGE,
			IpAddress: point.IPNetwork().IP,
			IpPrefix:  point.Prefix,
		}
	case IPv6Range:
		return &fabridpb.FABRIDConnectionPoint{
			Type:      fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_IPV6_RANGE,
			IpAddress: point.IPNetwork().IP,
			IpPrefix:  point.Prefix,
		}
	case Interface:
		return &fabridpb.FABRIDConnectionPoint{
			Type:      fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE,
			Interface: uint64(point.InterfaceId),
		}
	case Wildcard:
		return &fabridpb.FABRIDConnectionPoint{
			Type: fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_WILDCARD,
		}
	default:
		return &fabridpb.FABRIDConnectionPoint{}
	}
}

func ConnectionPointFromPB(point *fabridpb.FABRIDConnectionPoint) ConnectionPoint {
	switch point.Type {
	case fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_IPV4_RANGE:
		return ConnectionPoint{
			Type:   IPv4Range,
			IP:     net.IP(point.IpAddress).String(),
			Prefix: point.IpPrefix,
		}
	case fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_IPV6_RANGE:
		return ConnectionPoint{
			Type:   IPv6Range,
			IP:     net.IP(point.IpAddress).String(),
			Prefix: point.IpPrefix,
		}
	case fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_INTERFACE:
		return ConnectionPoint{
			Type:        Interface,
			InterfaceId: uint16(point.Interface),
		}
	case fabridpb.FABRIDConnectionType_FABRID_CONNECTION_TYPE_WILDCARD:
		return ConnectionPoint{Type: Wildcard}
	default:
		return ConnectionPoint{}
	}
}

func SupportedIndicesMapToPB(indicesMap SupportedIndicesMap) []*fabridpb.FABRIDIndexMapEntry {
	supIndices := make([]*fabridpb.FABRIDIndexMapEntry, 0)
	for ie, indices := range indicesMap {
		indicesu32 := make([]uint32, len(indices))
		for i, index := range indices {
			indicesu32[i] = uint32(index)
		}
		supIndices = append(supIndices, &fabridpb.FABRIDIndexMapEntry{
			IePair: &fabridpb.FABRIDIngressEgressPair{
				Ingress: ConnectionPointToPB(ie.Ingress),
				Egress:  ConnectionPointToPB(ie.Egress),
			},
			SupportedPolicyIndices: indicesu32,
		})

	}
	return supIndices
}

func SupportedIndicesMapFromPB(indicesMap []*fabridpb.FABRIDIndexMapEntry) SupportedIndicesMap {
	supIndices := make(SupportedIndicesMap, 0)
	for _, entry := range indicesMap {
		indicesu8 := make([]uint8, len(entry.SupportedPolicyIndices))
		for i, index := range entry.SupportedPolicyIndices {
			indicesu8[i] = uint8(index)
		}
		supIndices[ConnectionPair{
			Ingress: ConnectionPointFromPB(entry.IePair.Ingress),
			Egress:  ConnectionPointFromPB(entry.IePair.Egress),
		}] = indicesu8

	}
	return supIndices
}

func IndexIdentifierMapToPB(identifierMap IndexIdentifierMap) map[uint32]*fabridpb.
	FABRIDPolicyIdentifier {
	identMap := make(map[uint32]*fabridpb.FABRIDPolicyIdentifier, len(identifierMap))
	for index, identifier := range identifierMap {
		identMap[uint32(index)] = PolicyIdentifierToPB(identifier)
	}
	return identMap
}

func IndexIdentifierMapFromPB(identifierMap map[uint32]*fabridpb.
	FABRIDPolicyIdentifier) IndexIdentifierMap {
	identMap := make(IndexIdentifierMap, len(identifierMap))
	for index, identifier := range identifierMap {
		identMap[uint8(index)] = PolicyIdentifierFromPB(identifier)
	}
	return identMap
}

func DetachedToPB(detached *Detached) *fabridpb.FABRIDDetachedExtension {
	if detached == nil {
		return &fabridpb.FABRIDDetachedExtension{}
	}
	return &fabridpb.FABRIDDetachedExtension{
		Maps: &fabridpb.FABRIDDetachableMaps{
			SupportedIndicesMap: SupportedIndicesMapToPB(detached.SupportedIndicesMap),
			IndexIdentifierMap:  IndexIdentifierMapToPB(detached.IndexIdentiferMap),
		},
	}
}

func DetachedFromPB(detached *fabridpb.FABRIDDetachedExtension) *Detached {
	if detached == nil || detached.Maps == nil {
		return nil
	}
	return &Detached{
		SupportedIndicesMap: SupportedIndicesMapFromPB(detached.Maps.SupportedIndicesMap),
		IndexIdentiferMap:   IndexIdentifierMapFromPB(detached.Maps.IndexIdentifierMap),
	}
}

func (d *Detached) String() string {
	base := " indexIdentifierMap: ["
	for _, k := range d.IndexIdentiferMap.SortedKeys() {
		base += fmt.Sprintf("{ index: %d, is_local: %t, identifier: %d }", k,
			d.IndexIdentiferMap[k].IsLocal, d.IndexIdentiferMap[k].Identifier)
	}
	base += "], supportedIndicesMap: ["

	for _, k := range d.SupportedIndicesMap.SortedKeys() {
		base += fmt.Sprintf("{ ingress: { type: %s ", k.Ingress.Type)
		if k.Ingress.Type == Interface {
			base += fmt.Sprintf("interfaceId: %d }", k.Ingress.InterfaceId)
		} else if k.Ingress.Type == IPv4Range || k.Ingress.Type == IPv6Range {
			base += fmt.Sprintf("ip: %s, prefix: %d }", k.Ingress.IP, k.Ingress.Prefix)
		} else if k.Ingress.Type == Wildcard {
			base += "wildcard }"
		}

		base += fmt.Sprintf("} egress : { type: %s ", k.Egress.Type)
		if k.Egress.Type == Interface {
			base += fmt.Sprintf("interfaceId: %d } ", k.Egress.InterfaceId)
		} else if k.Egress.Type == IPv4Range || k.Egress.Type == IPv6Range {
			base += fmt.Sprintf("ip: %s, prefix: %d } ", k.Egress.IP, k.Egress.Prefix)
		} else if k.Ingress.Type == Wildcard {
			base += "wildcard }"
		}
		base += " supports: ["
		supported := d.SupportedIndicesMap[k]
		sort.Slice(supported, func(i int, j int) bool {
			return supported[i] < supported[j]
		})
		for _, z := range supported {
			base += fmt.Sprintf("%d, ", z)
		}
		base += "] } "
	}
	return base
}

func (d *Detached) Hash() []byte {
	h := sha256.New()
	for _, k := range d.IndexIdentiferMap.SortedKeys() {
		_ = binary.Write(h, binary.BigEndian, k)
		_ = binary.Write(h, binary.BigEndian, d.IndexIdentiferMap[k].IsLocal)
		_ = binary.Write(h, binary.BigEndian, d.IndexIdentiferMap[k].Identifier)
	}
	for _, k := range d.SupportedIndicesMap.SortedKeys() {
		_ = binary.Write(h, binary.BigEndian, k.Ingress.Type)
		if k.Ingress.Type == Interface {
			_ = binary.Write(h, binary.BigEndian, k.Ingress.InterfaceId)
		} else if k.Ingress.Type == IPv4Range || k.Ingress.Type == IPv6Range {
			_ = binary.Write(h, binary.BigEndian, k.Ingress.Prefix)
			_ = binary.Write(h, binary.BigEndian, k.Ingress.IP)
		}

		_ = binary.Write(h, binary.BigEndian, k.Egress.Type)
		if k.Egress.Type == Interface {
			_ = binary.Write(h, binary.BigEndian, k.Egress.InterfaceId)
		} else if k.Egress.Type == IPv4Range || k.Egress.Type == IPv6Range {
			_ = binary.Write(h, binary.BigEndian, k.Egress.Prefix)
			_ = binary.Write(h, binary.BigEndian, k.Egress.IP)
		}
		supported := d.SupportedIndicesMap[k]
		sort.Slice(supported, func(i int, j int) bool {
			return supported[i] < supported[j]
		})
		_ = binary.Write(h, binary.BigEndian, supported)
	}
	return h.Sum(nil)[0:digest.DigestLength]
}
