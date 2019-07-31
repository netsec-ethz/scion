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

package drkeystorage

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkey/drkeydbsqlite"
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
	// DefaultDuration is the default duration for the drkey SV and derived keys
	DefaultDuration = "24h"
)

const (
	// BackendKey is the backend key in the config mapping.
	BackendKey = "backend"
	// ConnectionKey is the connection key in the config mapping.
	ConnectionKey = "connection"
	// MaxOpenConnsKey is the key for max open conns in the config mapping.
	MaxOpenConnsKey = "maxopenconns"
	// MaxIdleConnsKey is the key for max idle conns in the config mapping.
	MaxIdleConnsKey = "maxidleconns"
	// DurationKey is the key for the key duration.
	DurationKey = "duration"
)

var _ (config.Config) = (*DRKeyDBConf)(nil)

// DRKeyDBConf is the configuration for the connection to the trust database.
type DRKeyDBConf map[string]string

// InitDefaults chooses the sqlite backend if no backend is set and sets all keys
// to lower case.
func (cfg *DRKeyDBConf) InitDefaults() {
	if *cfg == nil {
		*cfg = make(DRKeyDBConf)
	}
	m := *cfg
	util.LowerKeys(m)
	if cfg.Backend() == backendNone {
		m[BackendKey] = string(BackendSqlite)
	}
	if cfg.Duration() == 0 {
		m[DurationKey] = DefaultDuration
	}
}

// Backend returns the database backend type.
func (cfg *DRKeyDBConf) Backend() Backend {
	return Backend((*cfg)[BackendKey])
}

// Connection returns the database connection information.
func (cfg *DRKeyDBConf) Connection() string {
	return (*cfg)[ConnectionKey]
}

// MaxOpenConns returns the limit for maximum open connections to the database.
func (cfg *DRKeyDBConf) MaxOpenConns() (int, bool) {
	val, ok, _ := cfg.parsedInt(MaxOpenConnsKey)
	return val, ok
}

// MaxIdleConns returns the limit for maximum idle connections to the database.
func (cfg *DRKeyDBConf) MaxIdleConns() (int, bool) {
	val, ok, _ := cfg.parsedInt(MaxIdleConnsKey)
	return val, ok
}

func (cfg *DRKeyDBConf) parsedInt(key string) (int, bool, error) {
	val := (*cfg)[key]
	if val == "" {
		return 0, false, nil
	}
	i, err := strconv.Atoi(val)
	return i, true, err
}

// Duration returns the duration configured for the DRKey store.
func (cfg *DRKeyDBConf) Duration() time.Duration {
	d, _ := cfg.parseDuration(DurationKey)
	return d
}

func (cfg *DRKeyDBConf) parseDuration(key string) (time.Duration, error) {
	s := (*cfg)[key]
	dur, err := util.ParseDuration(s)
	if err != nil {
		return 0, common.NewBasicError("Not a duration", nil, "value", s)
	}
	return dur, nil
}

// Enabled returns true if DRKey is configured. False otherwise.
func (cfg *DRKeyDBConf) Enabled() bool {
	m := *cfg
	_, found := m[BackendKey]
	if !found {
		return false
	}
	_, found = m[ConnectionKey]
	if !found {
		return false
	}
	_, found = m[DurationKey]
	if !found {
		return false
	}
	return true
}

// Validate validates that all values are parsable, and the backend is set.
func (cfg *DRKeyDBConf) Validate() error {
	if !cfg.Enabled() {
		return nil
	}
	if err := cfg.validateLimits(); err != nil {
		return err
	}
	switch cfg.Backend() {
	case BackendSqlite:
		break
	case backendNone:
		return common.NewBasicError("No backend set", nil)
	default:
		return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
	}
	if _, err := cfg.parseDuration(DurationKey); err != nil {
		return err
	}
	return nil
}

func (cfg *DRKeyDBConf) validateLimits() error {
	if _, _, err := cfg.parsedInt(MaxOpenConnsKey); err != nil {
		return common.NewBasicError("Invalid MaxOpenConns", nil, "value", (*cfg)[MaxOpenConnsKey])
	}
	if _, _, err := cfg.parsedInt(MaxIdleConnsKey); err != nil {
		return common.NewBasicError("Invalid MaxIdleConns", nil, "value", (*cfg)[MaxIdleConnsKey])
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *DRKeyDBConf) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(drkeyDBSample, ctx[config.ID]))
}

// ConfigName is the key in the toml file.
func (cfg *DRKeyDBConf) ConfigName() string {
	return "drkey"
}

// New creates a drkey.DB from the config.
func (cfg *DRKeyDBConf) New() (drkey.DB, error) {
	log.Info("Connecting DRKeyDB", "backend", cfg.Backend(), "connection", cfg.Connection())
	var err error
	var db drkey.DB

	switch cfg.Backend() {
	case BackendSqlite:
		db, err = drkeydbsqlite.New(cfg.Connection())
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
	}
	if err != nil {
		return nil, err
	}
	setConnLimits(cfg, db)
	return db, nil
}

// NewStore creates a new beacon store backed by the configured database.
func (cfg *DRKeyDBConf) NewStore() (Store, error) {
	db, err := cfg.New()
	if err != nil {
		return nil, err
	}
	return drkey.NewStore(db), nil
}

func setConnLimits(cfg *DRKeyDBConf, db drkey.DB) {
	if m, ok := cfg.MaxOpenConns(); ok {
		db.SetMaxOpenConns(m)
	}
	if m, ok := cfg.MaxIdleConns(); ok {
		db.SetMaxIdleConns(m)
	}
}
