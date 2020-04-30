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

package drkey

import "bytes"

// DRKey represents a raw binary key
type DRKey []byte

func (k DRKey) String() string {
	return "[redacted key]"
}

// Equal returns true if both DRKeys are identical
func (k DRKey) Equal(other DRKey) bool {
	return bytes.Compare(k, other) == 0
}
