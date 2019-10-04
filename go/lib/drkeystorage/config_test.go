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
	"os"
	"testing"
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
