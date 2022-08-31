// Copyright 2020 ETH Zurich, Anapaya Systems
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

package segment

import (
	"fmt"
	"strings"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

type IndexState uint8

// possible states of a segment reservation index.
const (
	IndexTemporary IndexState = iota
	IndexPending              // the index is confirmed, but not yet activated.
	IndexActive
)

// Index is a segment reservation index.
type Index struct {
	Idx        reservation.IndexNumber
	Expiration time.Time
	state      IndexState
	MinBW      reservation.BWCls
	MaxBW      reservation.BWCls
	AllocBW    reservation.BWCls
	Token      *reservation.Token
}

// NewIndex creates a new Index without yet linking it to any reservation.
func NewIndex(idx reservation.IndexNumber, expiration time.Time, state IndexState,
	minBW, maxBW, allocBW reservation.BWCls, token *reservation.Token) *Index {
	return &Index{
		Idx:        idx,
		Expiration: expiration,
		state:      state,
		MinBW:      minBW,
		MaxBW:      maxBW,
		AllocBW:    allocBW,
		Token:      token,
	}
}

// State returns the read-only state.
func (index *Index) State() IndexState {
	return index.state
}

// Indices is a collection of Index that implements IndicesInterface.
type Indices []Index

var _ base.IndicesInterface = (*Indices)(nil)

func (idxs Indices) Len() int                                     { return len(idxs) }
func (idxs Indices) GetIndexNumber(i int) reservation.IndexNumber { return idxs[i].Idx }
func (idxs Indices) GetExpiration(i int) time.Time                { return idxs[i].Expiration }
func (idxs Indices) GetAllocBW(i int) reservation.BWCls           { return idxs[i].AllocBW }
func (idxs Indices) GetToken(i int) *reservation.Token            { return idxs[i].Token }
func (idxs Indices) Rotate(i int) base.IndicesInterface {
	return append(idxs[i:], idxs[:i]...)
}

func (idxs Indices) String() string {
	strs := make([]string, len(idxs))
	for i, index := range idxs {
		strs[i] = fmt.Sprintf("%d:%s", index.Idx, index.Expiration)
	}
	return strings.Join(strs, ",")
}

func (idxs Indices) OldestExp() time.Time {
	switch len(idxs) {
	case 0:
		return time.Time{}
	case 1:
		return idxs[0].Expiration
	default:
		exp := idxs[0].Expiration
		for i := 1; i < len(idxs); i++ {
			if idxs[i].Expiration.Before(exp) {
				exp = idxs[i].Expiration
			}
		}
		return exp
	}
}

func (idxs Indices) NewestExp() time.Time {
	switch len(idxs) {
	case 0:
		return time.Time{}
	case 1:
		return idxs[0].Expiration
	default:
		exp := idxs[0].Expiration
		for i := 1; i < len(idxs); i++ {
			if idxs[i].Expiration.After(exp) {
				exp = idxs[i].Expiration
			}
		}
		return exp
	}
}

// IndexFilter returns true if the index is to be kept.
// Returning false ensures the index is filtered out.
type IndexFilter func(Index) bool

// Filter uses the functional filters to return a list of indices where no index
// returned false in their filters.
func (idxs Indices) Filter(filters ...IndexFilter) Indices {
	valid := make(Indices, 0)
	for _, index := range idxs {
		compliant := true
		for _, filter := range filters {
			if compliant = filter(index); !compliant {
				break
			}
		}
		if compliant {
			valid = append(valid, index)
		}
	}
	return valid
}

// ByExpiration filters out indices that expire on or before the specified time.
func ByExpiration(atLeastUntil time.Time) IndexFilter {
	return func(index Index) bool {
		return index.Expiration.After(atLeastUntil)
	}
}

// ByMinBW filters out all indices with a MinBW lower than specified.
func ByMinBW(minBW reservation.BWCls) IndexFilter {
	return func(index Index) bool {
		return index.MinBW >= minBW
	}
}

// ByMax filters out all indices with a MaxBW higher than specified.
func ByMaxBW(maxBW reservation.BWCls) IndexFilter {
	return func(index Index) bool {
		return index.MaxBW <= maxBW
	}
}

// NotConfirmed filters out indices that are not in a state active or pending.
func NotConfirmed() IndexFilter {
	return func(index Index) bool {
		return index.state == IndexActive || index.state == IndexPending
	}
}

// NotSwitchableFrom filters out indices not reachable from the argument.
// A typical use would be to pass the active index to filter all non confirmed non future indices.
func NotSwitchableFrom(index *Index) IndexFilter {
	var heatDeathOfTheUniverse = time.Unix(1<<63-62135596801, 999999999) // aka infinity
	atLeastUntil := heatDeathOfTheUniverse
	if index != nil {
		atLeastUntil = index.Expiration.Add(-time.Nanosecond) // so "A" is switchable from "A"
	}
	return func(ind Index) bool {
		return NotConfirmed()(ind) && ByExpiration(atLeastUntil)(ind)
	}
}
