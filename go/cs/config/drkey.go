// Copyright 2019 ETH Zurich
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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/storage"
)

const (
	// DefaultEpochDuration is the default duration for the drkey SV and derived keys
	DefaultEpochDuration = 24 * time.Hour
	// DefaultMaxReplyAge is the default allowed age for replies.
	DefaultMaxReplyAge = 2 * time.Second
)

var _ (config.Config) = (*DRKeyConfig)(nil)

// DRKeyConfig is the configuration for the connection to the trust database.
type DRKeyConfig struct {
	// enabled is set to true if we find all the required fields in the configuration.
	enabled bool
	// DRKeyDB contains the DRKey DB configuration.
	DRKeyDB storage.DBConfig `toml:"drkey_db,omitempty"`
	// EpochDuration is the duration of the keys in this CS.
	EpochDuration util.DurWrap `toml:"epoch_duration,omitempty"`
	// MaxReplyAge is the age limit for a level 1 reply to be accepted. Older are rejected.
	MaxReplyAge util.DurWrap `toml:"max_reply_age,omitempty"`
	// AuthorizedDelegations is the DelegationList for this CS.
	Delegation DelegationList `toml:"delegation,omitempty"`

	//TLS config
	CertFile string `toml:"cert_file,omitempty"`
	KeyFile  string `toml:"key_file,omitempty"`
}

// NewDRKeyConfig returns a pointer to a valid, empty configuration.
func NewDRKeyConfig() *DRKeyConfig {
	c := DRKeyConfig{
		DRKeyDB:    storage.DBConfig{},
		Delegation: DelegationList{},
	}
	return &c
}

// InitDefaults initializes values of unset keys and determines if the configuration enables DRKey.
func (cfg *DRKeyConfig) InitDefaults() {
	cfg.enabled = true
	if cfg.EpochDuration.Duration == 0 {
		cfg.EpochDuration.Duration = DefaultEpochDuration
	}
	if cfg.MaxReplyAge.Duration == 0 {
		cfg.MaxReplyAge.Duration = DefaultMaxReplyAge
	}
	config.InitAll(&cfg.DRKeyDB, &cfg.Delegation)
	if cfg.DRKeyDB.Connection == "" {
		cfg.enabled = false
	}
}

// Enabled returns true if DRKey is configured. False otherwise.
func (cfg *DRKeyConfig) Enabled() bool {
	// TODO(juagargi): check that disabled CSs can receive DRKey queries from sciond (mine crashes)
	return cfg.enabled
}

// Validate validates that all values are parsable.
func (cfg *DRKeyConfig) Validate() error {
	if !cfg.Enabled() {
		return nil
	}
	return config.ValidateAll(&cfg.DRKeyDB, &cfg.Delegation)
}

// Sample writes a config sample to the writer.
func (cfg *DRKeyConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeySample)
	config.WriteSample(dst, path,
		config.CtxMap{config.ID: idSample},
		config.OverrideName(
			config.FormatData(
				&cfg.DRKeyDB,
				storage.SetID(storage.SampleDRKeyDB, idSample).Connection,
			),
			"drkey_db",
		),
		&cfg.Delegation,
	)
}

// ConfigName is the key in the toml file.
func (cfg *DRKeyConfig) ConfigName() string {
	return "drkey"
}

// DelegationList configures which endhosts can get delegation secrets, per protocol.
type DelegationList map[string][]string

var _ (config.Config) = (*DelegationList)(nil)

// InitDefaults will not add or modify any entry in the config.
func (cfg *DelegationList) InitDefaults() {
	if *cfg == nil {
		*cfg = make(DelegationList)
	}
}

// Validate validates that the protocols exist, and their addresses are parsable.
func (cfg *DelegationList) Validate() error {
	for proto, list := range *cfg {
		if _, found := protocol.KnownDerivations[proto]; !found {
			return common.NewBasicError("Configured protocol not found", nil, "protocol", proto)
		}
		for _, ip := range list {
			if h := addr.HostFromIPStr(ip); h == nil {
				return common.NewBasicError("Syntax error: not a valid address", nil, "ip", ip)
			}
		}
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *DelegationList) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeyDelegationListSample)
}

// ConfigName is the key in the toml file.
func (cfg *DelegationList) ConfigName() string {
	return "delegation"
}

// ToMapPerHost will return map where there is a set of supported protocols per host.
func (cfg *DelegationList) ToMapPerHost() map[[16]byte]map[string]struct{} {
	m := make(map[[16]byte]map[string]struct{})
	for proto, ipList := range *cfg {
		for _, ip := range ipList {
			host := addr.HostFromIPStr(ip)
			if host == nil {
				continue
			}
			var rawHost [16]byte
			copy(rawHost[:], host.IP().To16())
			protoSet := m[rawHost]
			if protoSet == nil {
				protoSet = make(map[string]struct{})
			}
			protoSet[proto] = struct{}{}
			m[rawHost] = protoSet
		}
	}
	return m
}
