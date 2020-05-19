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
	"github.com/stretchr/testify/require"
)

func TestDelegationListDefaults(t *testing.T) {
	var cfg DelegationList
	cfg.InitDefaults()
	require.NotNil(t, cfg)
	require.Empty(t, cfg)
}

func TestDelegationListSyntax(t *testing.T) {
	var cfg DelegationList
	sample1 := `piskes = ["1.1.1.1"]`
	meta, err := toml.Decode(sample1, &cfg)
	require.NoError(t, err)
	require.Empty(t, meta.Undecoded())
	require.NoError(t, cfg.Validate())

	sample2 := `piskes = ["not an address"]`
	meta, err = toml.Decode(sample2, &cfg)
	require.NoError(t, err)
	require.Empty(t, meta.Undecoded())
	require.Error(t, cfg.Validate())
}

func TestToMapPerHost(t *testing.T) {
	var cfg DelegationList
	sample := `piskes = ["1.1.1.1", "2.2.2.2"]
	scmp = ["1.1.1.1"]`
	toml.Decode(sample, &cfg)
	require.NoError(t, cfg.Validate())
	m := cfg.ToMapPerHost()
	require.Len(t, m, 2)

	var rawIP [16]byte
	copy(rawIP[:], net.ParseIP("1.1.1.1").To16())
	require.Len(t, m[rawIP], 2)
	require.Contains(t, m[rawIP], "piskes")
	require.Contains(t, m[rawIP], "scmp")

	copy(rawIP[:], net.ParseIP("2.2.2.2").To16())
	require.Len(t, m[rawIP], 1)
	require.Contains(t, m[rawIP], "piskes")
}

func TestInitDRKeyDBDefaults(t *testing.T) {
	var cfg DRKeyDBConf
	cfg.InitDefaults()
	require.NoError(t, cfg.Validate())
	require.EqualValues(t, "sqlite", cfg.Backend())
	require.Empty(t, cfg.Connection())
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
	require.NoError(t, err)
	require.NotNil(t, db)
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
	require.NoError(t, err)
	require.NotNil(t, db)
}

func tempFile(t *testing.T) string {
	file, err := ioutil.TempFile("", "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	return name
}
