// Copyright 2018 ETH Zurich
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

package drkey

import (
	"time"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
)

// Epoch represents a validity period.
type Epoch struct {
	scrypto.Validity
}

// Equal returns true if both Epochs are identical.
func (e Epoch) Equal(other Epoch) bool {
	return e.NotBefore.Time == other.NotBefore.Time &&
		e.NotAfter.Time == other.NotAfter.Time
}

// NewEpoch constructs an Epoch from its uint32 encoded begin and end parts.
func NewEpoch(begin, end uint32) Epoch {
	return Epoch{
		scrypto.Validity{
			NotBefore: util.UnixTime{Time: util.SecsToTime(begin)},
			NotAfter:  util.UnixTime{Time: util.SecsToTime(end)},
		},
	}
}

// Contains indicates whether the time point is inside this Epoch.
func (e *Epoch) Contains(t time.Time) bool {
	return e.Contains(t)
}
