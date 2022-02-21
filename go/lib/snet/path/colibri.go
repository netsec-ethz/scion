// Copyright 2022 ETH Zurich
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

package path

import (
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

// Colibri represents a colibri path in the data plane. For now, only static MACs are supported.
type Colibri struct {
	// Raw is the raw representation of this path.
	Raw []byte
}

func (p Colibri) SetPath(s *slayers.SCION) error {
	var colPath colibri.ColibriPathMinimal
	if err := colPath.DecodeFromBytes(p.Raw); err != nil {
		return err
	}
	colPath.InfoField.OrigPayLen = s.PayloadLen
	s.Path, s.PathType = &colPath, colPath.Type()
	return nil
}
