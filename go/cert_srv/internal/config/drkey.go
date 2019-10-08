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

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/util"
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
	DRKeyDB drkeystorage.DRKeyDBConf
	// EpochDuration is the duration of the keys in this CS.
	EpochDuration util.DurWrap
	// MaxReplyAge is the age limit for a level 1 reply to be accepted. Older are rejected.
	MaxReplyAge util.DurWrap
	// AuthorizedDelegations is the DelegationList for this CS.
	Delegation drkeystorage.DelegationList
}

// NewDRKeyConfig returns a pointer to a valid, empty configuration.
func NewDRKeyConfig() *DRKeyConfig {
	c := DRKeyConfig{
		DRKeyDB:    drkeystorage.DRKeyDBConf{},
		Delegation: drkeystorage.DelegationList{},
	}
	return &c
}

// InitDefaults initializes values of unset keys and determines if the configuration enables DRKey.
func (cfg *DRKeyConfig) InitDefaults() {
	cfg.enabled = true
	if cfg.EpochDuration.Duration == 0 {
		cfg.enabled = false
		cfg.EpochDuration.Duration = DefaultEpochDuration
	}
	if cfg.MaxReplyAge.Duration == 0 {
		cfg.MaxReplyAge.Duration = DefaultMaxReplyAge
	}
	config.InitAll(&cfg.DRKeyDB, &cfg.Delegation)
	if cfg.DRKeyDB.Connection() == "" {
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
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.DRKeyDB, &cfg.Delegation)
}

// ConfigName is the key in the toml file.
func (cfg *DRKeyConfig) ConfigName() string {
	return "drkey"
}

// NewDB creates a drkey.DB from the config.
func (cfg *DRKeyConfig) NewDB() (drkey.Lvl1DB, error) {
	return cfg.DRKeyDB.NewLvl1DB()
}
