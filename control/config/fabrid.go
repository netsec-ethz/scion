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

package config

import (
	"io"
	"net"
	"slices"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"github.com/scionproto/scion/private/config"
)

type FABRIDPolicy struct {
	IsLocalPolicy    bool                     `yaml:"local,omitempty"`
	LocalIdentifier  uint32                   `yaml:"local_identifier,omitempty"`
	LocalDescription string                   `yaml:"local_description,omitempty"`
	GlobalIdentifier uint32                   `yaml:"global_identifier,omitempty"`
	SupportedBy      []FABRIDConnectionPoints `yaml:"connections,omitempty"`
}

// Validate validates that all values are parsable.
func (cfg *FABRIDPolicy) Validate(asInterfaceIDs []uint16) error {
	for _, connectionPoints := range cfg.SupportedBy {
		if err := connectionPoints.Validate(asInterfaceIDs); err != nil {
			return serrors.WrapStr("Failed to validate connection points", err)
		}
	}
	if cfg.IsLocalPolicy {
		if cfg.LocalIdentifier == 0 {
			return serrors.New("Local policy identifier missing.")
		} else if cfg.LocalDescription == "" {
			return serrors.New("Local policy description missing.")
		} else if cfg.GlobalIdentifier != 0 {
			return serrors.New("Unexpected global identifier",
				"global_identifier", cfg.GlobalIdentifier)
		}
	} else {
		if cfg.GlobalIdentifier == 0 {
			return serrors.New("Global policy identifier missing.")
		} else if cfg.LocalDescription != "" {
			return serrors.New("Unexpected local description",
				"local_description", cfg.LocalDescription)
		} else if cfg.LocalIdentifier != 0 {
			return serrors.New("Unexpected local identifier",
				"local_identifier", cfg.LocalIdentifier)
		}
	}

	return nil
}

// Sample writes a config sample to the writer.
func (cfg *FABRIDPolicy) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fabridLocalPolicySample)
}

type FABRIDConnectionPoints struct {
	Ingress   FABRIDConnectionPoint `yaml:"ingress,omitempty"`
	Egress    FABRIDConnectionPoint `yaml:"egress,omitempty"`
	MPLSLabel uint32                `yaml:"mpls_label,omitempty"`
}

// Validate validates that all values are parsable.
func (cfg *FABRIDConnectionPoints) Validate(asInterfaceIDs []uint16) error {
	if cfg.Ingress.Type != fabrid.Interface && cfg.Ingress.Type != fabrid.Wildcard {
		return serrors.New("FABRID policies are only supported from an interface to an IP" +
			" range or other interface.")
	} else if cfg.Ingress.Type == fabrid.Interface && cfg.Egress.Type == fabrid.Interface && cfg.
		Ingress.Interface == cfg.Egress.Interface {
		return serrors.New("Interfaces should be distinct.")
	}
	if err := cfg.Ingress.Validate(asInterfaceIDs); err != nil {
		return serrors.WrapStr("Failed to validate ingress connection point", err)
	}
	if err := cfg.Egress.Validate(asInterfaceIDs); err != nil {
		return serrors.WrapStr("Failed to validate egress connection point", err)
	}

	return nil
}

// FABRIDConnectionPoint describes a specific interface, or an IP range. A FABRID policy can be
// supported on a pair of connection points.
type FABRIDConnectionPoint struct {
	Type      fabrid.ConnectionPointType `yaml:"type,omitempty"`
	IPAddress string                     `yaml:"ip,omitempty"`
	Prefix    uint8                      `yaml:"prefix,omitempty"`
	Interface uint16                     `yaml:"interface,omitempty"`
}

// Validate validates that all values are parsable.
func (cfg *FABRIDConnectionPoint) Validate(asInterfaceIDs []uint16) error {
	switch strings.ToLower(string(cfg.Type)) {
	case string(fabrid.Wildcard):
		cfg.Type = fabrid.Wildcard
	case string(fabrid.IPv4Range):
		cfg.Type = fabrid.IPv4Range
		if net.ParseIP(cfg.IPAddress).To4() == nil {
			return serrors.New("Invalid IPv4 address for connection point",
				"ip", cfg.IPAddress)
		} else if cfg.Prefix > 32 {
			return serrors.New("IPv4 prefix too large",
				"ip", cfg.IPAddress, "prefix", cfg.Prefix)
		}
	case string(fabrid.IPv6Range):
		cfg.Type = fabrid.IPv6Range
		ip := net.ParseIP(cfg.IPAddress)
		if ip == nil || len(ip) != net.IPv6len {
			return serrors.New("Invalid IPv6 address for connection point",
				"ip", cfg.IPAddress)
		} else if cfg.Prefix > 128 {
			return serrors.New("IPv6 prefix too large",
				"ip", cfg.IPAddress, "prefix", cfg.Prefix)
		}
	case string(fabrid.Interface):
		cfg.Type = fabrid.Interface
		if cfg.Interface == 0 {
			return serrors.New("Interface ID missing", "type", cfg.Type)
		}
		if !slices.Contains(asInterfaceIDs, cfg.Interface) {
			return serrors.New("Interface does not exist", "interface", cfg.Interface)
		}
	default:
		return serrors.New("Unknown FABRID connection point", "type", cfg.Type)
	}

	if cfg.Type != fabrid.Interface && cfg.Interface != 0 {
		return serrors.New("Unexpected interface ID", "type", cfg.Type)
	} else if cfg.Type != fabrid.IPv4Range && cfg.Type != fabrid.IPv6Range {
		if cfg.IPAddress != "" {
			return serrors.New("Unexpected IP address", "type", cfg.Type, "ip", cfg.IPAddress)
		} else if cfg.Prefix != 0 {
			return serrors.New("Unexpected prefix", "type", cfg.Type, "prefix", cfg.Prefix)
		}
	}
	return nil
}
