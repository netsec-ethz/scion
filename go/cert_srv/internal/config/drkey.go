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
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/drkeydbsqlite"
	"github.com/scionproto/scion/go/lib/drkey/protocol"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
)

// Backend indicates the database backend type.
type Backend string

const (
	// backendNone is the empty backend. It defaults to sqlite.
	backendNone Backend = ""
	// BackendSqlite indicates an sqlite backend.
	BackendSqlite Backend = "sqlite"
	// DefaultEpochDuration is the default duration for the drkey SV and derived keys
	DefaultEpochDuration = 24 * time.Hour
	// DefaultMaxReplyAge is the default allowed age for replies.
	DefaultMaxReplyAge = 2 * time.Second
)

var _ (config.Config) = (*DRKeyConfig)(nil)

// DRKeyConfig is the configuration for the connection to the trust database.
type DRKeyConfig struct {
	// enabled is set to true if we find all the required fields in the configuration
	enabled bool
	// Backend is the backend key in the config mapping.
	Backend Backend
	// Connection is the connection key in the config mapping.
	Connection string
	// MaxOpenConns is the key for max open conns in the config mapping.
	MaxOpenConns string
	// MaxIdleConns is the key for max idle conns in the config mapping.
	MaxIdleConns string
	// EpochDuration is the duration of the keys in this CS.
	EpochDuration util.DurWrap
	// Protocols is the map between protocol name and derivation.
	Protocols ProtocolMap
	// MaxReplyAge is the age limit for a level 1 reply to be accepted. Older are rejected.
	MaxReplyAge util.DurWrap
}

// InitDefaults initializes values of unset keys and determines if the configuration enables DRKey.
func (cfg *DRKeyConfig) InitDefaults() {
	cfg.enabled = true
	if cfg.Backend == backendNone {
		cfg.Backend = BackendSqlite
	}
	if cfg.EpochDuration.Duration == 0 {
		cfg.enabled = false
		cfg.EpochDuration.Duration = DefaultEpochDuration
	}
	if cfg.MaxReplyAge.Duration == 0 {
		cfg.MaxReplyAge.Duration = DefaultMaxReplyAge
	}
	if cfg.Connection == "" {
		cfg.enabled = false
	}
}

// Enabled returns true if DRKey is configured. False otherwise.
func (cfg *DRKeyConfig) Enabled() bool {
	// TODO(juagargi): check that disabled CSs can receive DRKey queries from sciond (mine crashes)
	return cfg.enabled
}

// Validate validates that all values are parsable, and the backend is set.
func (cfg *DRKeyConfig) Validate() error {
	if !cfg.Enabled() {
		return nil
	}
	switch cfg.Backend {
	case BackendSqlite:
		break
	case backendNone:
		return common.NewBasicError("No backend set", nil)
	default:
		return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend)
	}
	if _, _, err := parsedInt(cfg.MaxOpenConns); err != nil {
		return err
	}
	if _, _, err := parsedInt(cfg.MaxIdleConns); err != nil {
		return err
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *DRKeyConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(drkeyDBSample, ctx[config.ID]))
	config.WriteSample(dst, path, ctx, &cfg.Protocols)
}

// ConfigName is the key in the toml file.
func (cfg *DRKeyConfig) ConfigName() string {
	return "drkey"
}

// NewDB creates a drkey.DB from the config.
func (cfg *DRKeyConfig) NewDB() (drkey.Lvl1DB, error) {
	log.Info("Connecting DRKeyDB", "backend", cfg.Backend, "connection", cfg.Connection)
	var err error
	var db drkey.Lvl1DB

	switch cfg.Backend {
	case BackendSqlite:
		db, err = drkeydbsqlite.NewLvl1Backend(cfg.Connection)
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend)
	}
	if err != nil {
		return nil, err
	}
	setConnLimits(cfg, db)
	return db, nil
}

func setConnLimits(cfg *DRKeyConfig, db drkey.Lvl1DB) {
	if v, found, _ := parsedInt(cfg.MaxOpenConns); found {
		db.SetMaxOpenConns(v)
	}
	if v, found, _ := parsedInt(cfg.MaxIdleConns); found {
		db.SetMaxIdleConns(v)
	}
}

// parsedInt returns the int value, flag indicating it was found, and the parsing error.
func parsedInt(val string) (int, bool, error) {
	if val == "" {
		return 0, false, nil
	}
	i, err := strconv.Atoi(val)
	return i, true, err
}

// ProtocolRegistry constructs a registry that represents this configuration.
func (cfg *DRKeyConfig) ProtocolRegistry() (protocol.Registry, error) {
	m := protocol.NewRegistry()
	for protoName, implName := range cfg.Protocols {
		if err := m.Register(protoName, implName); err != nil {
			return nil, common.NewBasicError("Bad protocol configuration", err)
		}
	}
	return m, nil
}

// ProtocolMap is the protocol name to implementation configuration map.
type ProtocolMap map[string]string

// ConfigName returns the configuration name of this block.
func (p *ProtocolMap) ConfigName() string {
	return "protocols"
}

// Sample returns a valid sample for this configuration map.
func (p *ProtocolMap) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeyProtocolsSample)
}
