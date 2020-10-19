// Copyright 2020 ETH Zurich
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

	"github.com/scionproto/scion/go/lib/addr"
)

// Lvl1Req represents a level 1 request between CS.
type Lvl1Req struct {
	DstIA     addr.IA
	ValTime   time.Time
	Timestamp time.Time
}

// NewLvl1Req returns a fresh Lvl1Req
func NewLvl1Req(dstIA addr.IA, valTime time.Time) Lvl1Req {
	return Lvl1Req{
		DstIA:     dstIA,
		ValTime:   valTime,
		Timestamp: time.Now(),
	}
}
