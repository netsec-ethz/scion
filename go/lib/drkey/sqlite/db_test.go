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

package sqlite

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/drkey/dbtest"
)

var _ dbtest.TestableSVDB = (*TestSVBackend)(nil)

type TestSVBackend struct {
	*SVBackend
}

func (b *TestSVBackend) Prepare(t *testing.T, _ context.Context) {
	db := newSVDatabase(t)
	b.SVBackend = db
}

func TestSVDBSuite(t *testing.T) {
	tdb := &TestSVBackend{}
	dbtest.TestSecretValueDB(t, tdb)
}

func newSVDatabase(t *testing.T) *SVBackend {
	dir := t.TempDir()
	file, err := ioutil.TempFile(dir, "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	db, err := NewSVBackend(name)
	require.NoError(t, err)
	return db
}

var _ dbtest.TestableLvl1DB = (*TestLvl1Backend)(nil)

type TestLvl1Backend struct {
	*Lvl1Backend
}

func (b *TestLvl1Backend) Prepare(t *testing.T, _ context.Context) {
	db := newLvl1Database(t)
	b.Lvl1Backend = db
}

func TestLvl1DBSuite(t *testing.T) {
	tdb := &TestLvl1Backend{}
	dbtest.TestLvl1(t, tdb)
}

func newLvl1Database(t *testing.T) *Lvl1Backend {
	dir := t.TempDir()
	file, err := ioutil.TempFile(dir, "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	db, err := NewLvl1Backend(name)
	require.NoError(t, err)
	return db
}

var _ dbtest.TestableLvl2DB = (*TestLvl2Backend)(nil)

type TestLvl2Backend struct {
	*Lvl2Backend
}

func (b *TestLvl2Backend) Prepare(t *testing.T, _ context.Context) {
	db := newLvl2Database(t)
	b.Lvl2Backend = db
}

func TestLvl2DBSuite(t *testing.T) {
	tdb := &TestLvl2Backend{}
	dbtest.TestLvl2(t, tdb)
}

func newLvl2Database(t *testing.T) *Lvl2Backend {
	dir := t.TempDir()
	file, err := ioutil.TempFile(dir, "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	db, err := NewLvl2Backend(name)
	require.NoError(t, err)
	return db
}
