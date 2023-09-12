// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	timeout  = time.Second
	flyover1 = &hummingbird.Flyover{
		BaseHop: hummingbird.BaseHop{
			IA:      xtest.MustParseIA("1-ff00:0:111"),
			Ingress: 42,
			Egress:  43,
		},
		ResID:     12345,
		Bw:        666,
		Ak:        [16]byte{1, 2, 3, 3, 3, 3},
		StartTime: 100,
		Duration:  10,
	}
	flyover2 = &hummingbird.Flyover{
		BaseHop: hummingbird.BaseHop{
			IA:      xtest.MustParseIA("1-ff00:0:112"),
			Ingress: 42,
			Egress:  43,
		},
		ResID:     12346,
		Bw:        666,
		Ak:        [16]byte{1, 2, 3, 3, 3, 3},
		StartTime: 333,
		Duration:  10,
	}
)

// TestOpenExisting tests that New does not overwrite an existing database if
// versions match.
func TestOpenExisting(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	b, tmpF := setupDB(t)
	defer cleanup(tmpF)

	// Insert a new flyover.
	f := &hummingbird.Flyover{
		BaseHop: hummingbird.BaseHop{
			IA:      xtest.MustParseIA("1-ff00:0:111"),
			Ingress: 42,
			Egress:  43,
		},
		ResID:     12345,
		Bw:        666,
		Ak:        [16]byte{1, 2, 3, 3, 3, 3},
		StartTime: 333,
		Duration:  10,
	}
	err := b.StoreFlyovers(ctx, []*hummingbird.Flyover{f})
	require.NoError(t, err)
	b.db.Close()

	// Open again.
	b, err = New(tmpF)
	require.NoError(t, err)
	// Check the flyover is present
	flyovers, err := b.GetFlyovers(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(flyovers))
	require.Equal(t, f, flyovers[0])
}

// TestOpenNewer tests that New does not overwrite an existing database if it's
// of a newer version.
func TestOpenNewer(t *testing.T) {
	b, tmpF := setupDB(t)
	defer cleanup(tmpF)
	// Write a newer version
	_, err := b.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1))
	require.NoError(t, err)
	b.db.Close()
	// Call
	b, err = New(tmpF)
	// Test
	assert.Error(t, err)
	assert.Nil(t, b)
}

func TestGetFlyovers(t *testing.T) {
	allFlyovers := []*hummingbird.Flyover{
		flyover1,
		flyover2,
	}
	testCases := map[string]struct {
		IAs      []string
		expected []*hummingbird.Flyover
	}{
		"nil-filter": {
			IAs:      nil,
			expected: []*hummingbird.Flyover{flyover1, flyover2},
		},
		"all": {
			IAs:      []string{},
			expected: []*hummingbird.Flyover{flyover1, flyover2},
		},
		"one": {
			IAs:      []string{"1-ff00:0:112"},
			expected: []*hummingbird.Flyover{flyover2},
		},
		"two": {
			IAs:      []string{"1-ff00:0:111", "1-ff00:0:112"},
			expected: []*hummingbird.Flyover{flyover1, flyover2},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			// Create new DB
			b, tmpF := setupDB(t)
			defer b.Close()
			defer cleanup(tmpF)

			// Insert all flyovers.
			err := b.StoreFlyovers(ctx, allFlyovers)
			require.NoError(t, err)

			// Retrieve.
			IAs := make([]addr.IA, len(tc.IAs))
			for i, ia := range tc.IAs {
				IAs[i] = xtest.MustParseIA(ia)
			}
			flyovers, err := b.GetFlyovers(ctx, IAs)
			require.NoError(t, err)
			// Check.
			require.EqualValues(t, tc.expected, flyovers)
		})
	}
}

func TestInsertUniqueFlyovers(t *testing.T) {
	// All flyovers have a unique (IA,resID)
	flyovers := []*hummingbird.Flyover{
		flyover1,
		flyover2,
	}

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	b, tmpF := setupDB(t)
	defer b.Close()
	defer cleanup(tmpF)

	// Store a sequence of flyovers.
	err := b.StoreFlyovers(ctx, flyovers)
	require.NoError(t, err)

	// Check stored flyovers.
	expected := flyovers
	flyovers, err = b.GetFlyovers(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, expected, flyovers)
}

func TestInsertNonUniqueFlyovers(t *testing.T) {
	// All flyovers have a unique (IA,resID)
	flyovers := []*hummingbird.Flyover{
		flyover1,
		flyover1,
	}

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	b, tmpF := setupDB(t)
	defer b.Close()
	defer cleanup(tmpF)

	// Store a sequence of flyovers.
	err := b.StoreFlyovers(ctx, flyovers)
	require.NoError(t, err)

	// Check stored flyovers.
	expected := []*hummingbird.Flyover{flyover1}
	flyovers, err = b.GetFlyovers(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, expected, flyovers)
}

func TestDeleteExpired(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	b, tmpF := setupDB(t)
	defer cleanup(tmpF)

	// Insert two flyovers. They (start,end) at (100,110)(333,343) respectively.
	allFlyovers := []*hummingbird.Flyover{flyover1, flyover2}
	err := b.StoreFlyovers(ctx, allFlyovers)
	require.NoError(t, err)

	// Expire as if time was now 10.
	n, err := b.deleteExpiredFlyovers(ctx, util.SecsToTime(0))
	require.NoError(t, err)
	require.Equal(t, 0, n)

	// Expire as if time was now 101.
	n, err = b.deleteExpiredFlyovers(ctx, util.SecsToTime(101))
	require.NoError(t, err)
	require.Equal(t, 0, n)

	// Expire as if time was now 111.
	n, err = b.deleteExpiredFlyovers(ctx, util.SecsToTime(111))
	require.NoError(t, err)
	require.Equal(t, 1, n) // one has been deleted
	// Check we still have flyover2.
	flyovers, err := b.GetFlyovers(ctx, nil)
	require.NoError(t, err)
	require.Len(t, flyovers, 1)
	require.Equal(t, flyover2, flyovers[0])

	// Expire as if time was now 500.
	n, err = b.deleteExpiredFlyovers(ctx, util.SecsToTime(500))
	require.NoError(t, err)
	require.Equal(t, 1, n) // one has been deleted
	// Check we don't have flyovers.
	flyovers, err = b.GetFlyovers(ctx, nil)
	require.NoError(t, err)
	require.Len(t, flyovers, 0)
}

func setupDB(t *testing.T) (*Backend, string) {
	tmpFile := tempFilename(t)
	b, err := New(tmpFile)
	// b, err := New("file::memory:")
	require.NoError(t, err, "Failed to open DB")
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	dir, err := os.MkdirTemp("", "hummingbirddb-sqlite")
	require.NoError(t, err)
	n := t.Name()
	n = strings.ReplaceAll(n, "/", "-")
	return path.Join(dir, n)
}

func cleanup(tmpFile string) {
	os.RemoveAll(filepath.Dir(tmpFile))
}
