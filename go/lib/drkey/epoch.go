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

	"github.com/scionproto/scion/go/lib/util"
)

type Epoch struct {
	Begin uint32
	End   uint32
}

func (e *Epoch) Length() uint32 {
	return e.End - e.Begin
}

func (e *Epoch) Nr(offset uint32) uint32 {
	l := e.Length()
	t := util.TimeToSecs(time.Now())
	nr := t / l
	if t < (nr*l + offset) {
		return nr - 1
	}
	return nr
}

func (e *Epoch) GetPreviousEpoch(length uint32) *Epoch {
	return &Epoch{Begin: e.Begin - length, End: e.Begin}
}

func (e *Epoch) GetNextEpoch(length uint32) *Epoch {
	return &Epoch{Begin: e.End, End: e.End + length}
}
