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

	"github.com/scionproto/scion/go/lib/addr"
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
)

// DRKeyDBConf is the configuration used to describe both a level 1 and 2 DRKey DB.
type DRKeyDBConf map[string]string

// DelegationList configures which endhosts can get delegation secrets, per protocol.
type DelegationList map[string][]string

var _ (config.Config) = (*DRKeyDBConf)(nil)
var _ (config.Config) = (*DelegationList)(nil)

// InitDefaults chooses the sqlite backend if no backend is set and sets all keys to lower case.
func (cfg *DRKeyDBConf) InitDefaults() {
	if *cfg == nil {
		*cfg = make(DRKeyDBConf)
	}
	m := *cfg
	util.LowerKeys(m)
	if cfg.Backend() == backendNone {
		m[BackendKey] = string(BackendSqlite)
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

// Validate validates that all values are parsable, and the backend is set.
func (cfg *DRKeyDBConf) Validate() error {
	if err := cfg.validateLimits(); err != nil {
		return err
	}
	switch cfg.Backend() {
	case BackendSqlite:
		return nil
	case backendNone:
		return common.NewBasicError("No backend set", nil)
	}
	return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
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
	config.WriteString(dst, fmt.Sprintf(drkeyLvl1DBSample, ctx[config.ID]))
}

// ConfigName is the key in the toml file.
func (cfg *DRKeyDBConf) ConfigName() string {
	return "drkeyDB"
}

// newDB is an internal function that returns a new drkey DB. Call this with a pointer to
// a function func(string)(drkey.Lvl1DB, error) (also drkey.Lvl2DB) such as
// drkeydbsqlite.NewLvl1Backend .
func (cfg *DRKeyDBConf) newDB(newdbFcn func(string) (drkey.BaseDB, error)) (drkey.BaseDB, error) {
	log.Info("Connecting DRKeyDB", "backend", cfg.Backend(), "connection", cfg.Connection())
	var err error
	var db drkey.BaseDB
	switch cfg.Backend() {
	case BackendSqlite:
		db, err = newdbFcn(cfg.Connection())
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
	}
	if err != nil {
		return nil, err
	}
	cfg.setConnLimits(db)
	return db, nil
}

// NewLvl1DB returns a new level 1 drkey DB.
func (cfg *DRKeyDBConf) NewLvl1DB() (drkey.Lvl1DB, error) {
	db, err :=
		cfg.newDB(func(s string) (drkey.BaseDB, error) { return drkeydbsqlite.NewLvl1Backend(s) })
	if err != nil {
		return nil, err
	}
	return db.(drkey.Lvl1DB), nil
}

// NewLvl2DB returns a new level 2 drkey DB.
func (cfg *DRKeyDBConf) NewLvl2DB() (drkey.Lvl2DB, error) {
	db, err :=
		cfg.newDB(func(s string) (drkey.BaseDB, error) { return drkeydbsqlite.NewLvl2Backend(s) })
	if err != nil {
		return nil, err
	}
	return db.(drkey.Lvl2DB), nil
}

func (cfg *DRKeyDBConf) setConnLimits(db drkey.BaseDB) {
	if m, ok := cfg.MaxOpenConns(); ok {
		db.SetMaxOpenConns(m)
	}
	if m, ok := cfg.MaxIdleConns(); ok {
		db.SetMaxIdleConns(m)
	}
}

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
