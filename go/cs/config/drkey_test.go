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
	"net"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/pkg/storage"
)

func TestInitDefaults(t *testing.T) {
	var cfg DRKeyConfig
	cfg.InitDefaults()
	assert.EqualValues(t, 24*time.Hour, cfg.EpochDuration.Duration)
	assert.EqualValues(t, 2*time.Second, cfg.MaxReplyAge.Duration)
}

func TestDRKeyConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg DRKeyConfig
	cfg.Sample(&sample, nil, nil)
	meta, err := toml.Decode(sample.String(), &cfg)
	require.NoError(t, err)
	require.Empty(t, meta.Undecoded())
	err = cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, DefaultEpochDuration, cfg.EpochDuration.Duration)
	assert.Equal(t, DefaultMaxReplyAge, cfg.MaxReplyAge.Duration)
}

func TestDisable(t *testing.T) {
	var cfg = NewDRKeyConfig()
	require.False(t, cfg.Enabled())
	var err error
	err = cfg.Validate()
	require.NoError(t, err)
	cfg.EpochDuration.Duration = 10 * time.Hour
	cfg.MaxReplyAge.Duration = 10 * time.Hour
	cfg.DRKeyDB.Connection = "a"
	cfg.InitDefaults()
	require.True(t, cfg.Enabled())
	err = cfg.Validate()
	require.NoError(t, err)
	assert.EqualValues(t, 10*time.Hour, cfg.EpochDuration.Duration)
	assert.EqualValues(t, 10*time.Hour, cfg.MaxReplyAge.Duration)
}

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

func TestNewLvl1DB(t *testing.T) {
	cfg := DRKeyConfig{}
	cfg.InitDefaults()
	cfg.DRKeyDB.Connection = tempFile(t)
	db, err := storage.NewDRKeyLvl1Storage(cfg.DRKeyDB)
	defer func() {
		db.Close()
		os.Remove(cfg.DRKeyDB.Connection)
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
