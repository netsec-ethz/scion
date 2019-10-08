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
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDelegationListDefaults(t *testing.T) {
	var cfg DelegationList
	cfg.InitDefaults()
	if cfg == nil {
		t.Errorf("InitDefaults should have initialized the map, but did not")
	}
	if len(cfg) != 0 {
		t.Errorf("InitDefaults should leave the map empty but is not: %+v", cfg)
	}
}

func TestDelegationListSyntax(t *testing.T) {
	var cfg DelegationList
	sample1 := `piskes = ["1.1.1.1"]`
	meta, err := toml.Decode(sample1, &cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(meta.Undecoded()) != 0 {
		t.Fatalf("Should be empty but it's not: %+v", meta.Undecoded())
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}

	sample2 := `piskes = ["not an address"]`
	meta, err = toml.Decode(sample2, &cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(meta.Undecoded()) != 0 {
		t.Fatalf("Should be empty but it's not: %+v", meta.Undecoded())
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Expected validation error but got none")
	}
}

func TestToMapPerHost(t *testing.T) {
	var cfg DelegationList
	sample := `piskes = ["1.1.1.1", "2.2.2.2"]
	scmp = ["1.1.1.1"]`
	toml.Decode(sample, &cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
	m := cfg.ToMapPerHost()
	if len(m) != 2 {
		t.Fatalf("The map should contain the two hosts. Map: %v", m)
	}

	var rawIP [16]byte
	copy(rawIP[:], net.ParseIP("1.1.1.1").To16())
	if len(m[rawIP]) != 2 {
		t.Fatalf("Expecting 2 protocols for 1.1.1.1. Content: %+v", m[rawIP])
	}
	if _, found := m[rawIP]["piskes"]; !found {
		t.Fatalf("Expected to find piskes for 1.1.1.1 but not. Content: %+v", m[rawIP])
	}
	if _, found := m[rawIP]["scmp"]; !found {
		t.Fatalf("Expected to find scmp for 1.1.1.1 but not. Content: %+v", m[rawIP])
	}

	copy(rawIP[:], net.ParseIP("2.2.2.2").To16())
	if len(m[rawIP]) != 1 {
		t.Fatalf("Expecting 1 protocol for 2.2.2.2 ; Content: %+v", m[rawIP])
	}
	if _, found := m[rawIP]["piskes"]; !found {
		t.Fatalf("Expected to find piskes for 2.2.2.2 but not. Content: %+v", m[rawIP])
	}
}

func TestInitDRKeyDBDefaults(t *testing.T) {
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
}

func TestNewLvl1DB(t *testing.T) {
	cfg := &DRKeyDBConf{
		"backend":    "sqlite",
		"connection": tempFile(t),
	}
	db, err := cfg.NewLvl1DB()
	defer func() {
		db.Close()
		os.Remove(cfg.Connection())
	}()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if db == nil {
		t.Fatal("Returned DB is nil")
	}
}

func TestNewLvl2DB(t *testing.T) {
	cfg := &DRKeyDBConf{
		"backend":    "sqlite",
		"connection": tempFile(t),
	}
	db, err := cfg.NewLvl2DB()
	defer func() {
		db.Close()
		os.Remove(cfg.Connection())
	}()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if db == nil {
		t.Fatal("Returned DB is nil")
	}
}

func tempFile(t *testing.T) string {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		t.Fatalf("unable to create temp file")
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close temp file")
	}
	return name
}
