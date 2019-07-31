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
	"bytes"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/scionproto/scion/go/lib/util"
)

func TestInitDefaults(t *testing.T) {
	var cfg DRKeyDBConf
	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(cfg.Backend()) != "sqlite" {
		t.Errorf("Unexpected configuration value: %v", cfg.Backend())
	}
	if cfg.Connection() != "" {
		t.Errorf("Unexpected configuration value: %v", cfg.Connection())
	}
	if cfg.Duration() != time.Hour*24 {
		t.Errorf("Unexpected configuration value: %v", cfg.Duration())
	}
}

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg DRKeyDBConf
	cfg.Sample(&sample, nil, nil)
	meta, err := toml.Decode(sample.String(), &cfg)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	util.LowerKeys(cfg)
	if len(meta.Undecoded()) != 0 {
		t.Errorf("Meta should be empty: %v", meta.Undecoded())
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestDisable(t *testing.T) {
	var cfg = make(DRKeyDBConf)
	if cfg.Enabled() == true {
		t.Error("Unexpected enabled set")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	cfg[DurationKey] = "10h"
	cfg[ConnectionKey] = "a"
	cfg[BackendKey] = "sqlite"
	if cfg.Enabled() != true {
		t.Error("Unexpected enabled unset")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}
