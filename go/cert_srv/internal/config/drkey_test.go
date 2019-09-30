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
	"bytes"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/drkey/protocol"
)

func TestInitDefaults(t *testing.T) {
	var cfg DRKeyConfig
	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(cfg.Backend) != "sqlite" {
		t.Errorf("Unexpected configuration value: %v", cfg.Backend)
	}
	if cfg.Connection != "" {
		t.Errorf("Unexpected configuration value: %v", cfg.Connection)
	}
	if cfg.EpochDuration.Duration != 24*time.Hour {
		t.Errorf("Unexpected configuration value: %v", cfg.EpochDuration)
	}
	if cfg.MaxReplyAge.Duration != 2*time.Second {
		t.Errorf("Unexpected configuration value: %v", cfg.EpochDuration)
	}
}

func TestDRKeyConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg DRKeyConfig
	cfg.Sample(&sample, nil, nil)
	meta, err := toml.Decode(sample.String(), &cfg)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(meta.Undecoded()) != 0 {
		t.Errorf("Meta should be empty: %v", meta.Undecoded())
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cfg.EpochDuration.Duration != DefaultEpochDuration {
		t.Errorf("Unexpected config value: %v", cfg.EpochDuration)
	}
	if cfg.MaxReplyAge.Duration != DefaultMaxReplyAge {
		t.Errorf("Unexpected config value: %v", cfg.MaxReplyAge)
	}
	if _, found := cfg.Protocols["foo"]; !found {
		t.Errorf("Protocol not found")
	}
}

func TestDisable(t *testing.T) {
	var cfg = DRKeyConfig{}
	if cfg.Enabled() == true {
		t.Error("Unexpected enabled set")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	cfg.EpochDuration.Duration = 10 * time.Hour
	cfg.MaxReplyAge.Duration = 10 * time.Hour
	cfg.Connection = "a"
	cfg.Backend = "sqlite"
	cfg.InitDefaults()
	if cfg.Enabled() != true {
		t.Error("Unexpected enabled unset")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cfg.EpochDuration.Duration != 10*time.Hour {
		t.Errorf("Unexpected config value: %v", cfg.EpochDuration)
	}
	if cfg.MaxReplyAge.Duration != 10*time.Hour {
		t.Errorf("Unexpected config value: %v", cfg.MaxReplyAge)
	}
}

func TestProtocols(t *testing.T) {
	// init protocols
	m := protocol.NewRegistry()
	// check the name of the two know implementations
	if err := m.Register("p1", "standard"); err != nil {
		t.Errorf("Standard implementation not found")
	}
	if err := m.Register("p2", "delegated"); err != nil {
		t.Errorf("Delegated implementation not found")
	}
}
