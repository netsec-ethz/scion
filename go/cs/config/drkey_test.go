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
	"io/ioutil"
	"os"
	"testing"

	toml "github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/pkg/storage"
)

func TestInitDefaults(t *testing.T) {
	var cfg DRKeyConfig
	cfg.InitDefaults()
	assert.EqualValues(t, DefaultPrefetchEntries, cfg.PrefetchEntries)
	assert.NotNil(t, cfg.Delegation)
}

func TestSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg DRKeyConfig
	cfg.Sample(&sample, nil, nil)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	require.NoError(t, err)
	err = cfg.Validate()
	require.NoError(t, err)
}

func TestDisable(t *testing.T) {
	cases := []struct {
		name          string
		prepareCfg    func(cfg *DRKeyConfig)
		expectEnabled bool
	}{
		{
			name:          "default",
			expectEnabled: false,
		},
		{
			name: "with CacheEntries",
			prepareCfg: func(cfg *DRKeyConfig) {
				cfg.PrefetchEntries = 100
			},
			expectEnabled: false,
		},
		{
			name: "with Lvl1DB",
			prepareCfg: func(cfg *DRKeyConfig) {
				cfg.Lvl1DB.Connection = "test"
			},
			expectEnabled: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &DRKeyConfig{}
			cfg.InitDefaults()
			if c.prepareCfg != nil {
				c.prepareCfg(cfg)
			}
			require.NoError(t, cfg.Validate())
			assert.Equal(t, c.expectEnabled, cfg.Enabled())
		})
	}
}

func TestSVHostListDefaults(t *testing.T) {
	var cfg SVHostList
	cfg.InitDefaults()
	require.NotNil(t, cfg)
	require.Empty(t, cfg)
}

func TestSVHostListSyntax(t *testing.T) {
	var cfg SVHostList
	var err error
	sample1 := `scmp = ["1.1.1.1"]`
	err = toml.NewDecoder(bytes.NewReader([]byte(sample1))).Strict(true).Decode(&cfg)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())

	sample2 := `scmp = ["not an address"]`
	err = toml.NewDecoder(bytes.NewReader([]byte(sample2))).Strict(true).Decode(&cfg)
	require.NoError(t, err)
	require.Error(t, cfg.Validate())
}

func TestToMapPerHost(t *testing.T) {
	var cfg SVHostList
	sample := `dns = ["1.1.1.1", "2.2.2.2"]
	scmp = ["1.1.1.1"]`
	ip1111, err := netaddr.ParseIP("1.1.1.1")
	require.NoError(t, err)
	ip2222, err := netaddr.ParseIP("2.2.2.2")
	require.NoError(t, err)
	err = toml.NewDecoder(bytes.NewReader([]byte(sample))).Strict(true).Decode(&cfg)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	m := cfg.ToAllowedSet()

	require.Len(t, m, 3)
	require.Contains(t, m, HostProto{
		Host:  ip1111,
		Proto: drkey.DNS,
	})
	require.Contains(t, m, HostProto{
		Host:  ip2222,
		Proto: drkey.DNS,
	})
	require.Contains(t, m, HostProto{
		Host:  ip1111,
		Proto: drkey.SCMP,
	})
}

func TestNewLvl1DB(t *testing.T) {
	cfg := DRKeyConfig{}
	cfg.InitDefaults()
	cfg.Lvl1DB.Connection = tempFile(t)
	db, err := storage.NewDRKeyLvl1Storage(cfg.Lvl1DB)
	defer func() {
		db.Close()
		os.Remove(cfg.Lvl1DB.Connection)
	}()
	require.NoError(t, err)
	require.NotNil(t, db)
}

func TestNewSVDB(t *testing.T) {
	cfg := DRKeyConfig{}
	cfg.InitDefaults()
	cfg.SVDB.Connection = tempFile(t)
	db, err := storage.NewDRKeySVStorage(cfg.SVDB)
	defer func() {
		db.Close()
		os.Remove(cfg.Lvl1DB.Connection)
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
