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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
)

// Colibri represents a Colibri path in the data plane. For now, only static MACs are supported.
type Colibri struct {
	colibri.ColibriPathMinimal
}

var _ snet.DataplanePath = Colibri{}

func (p Colibri) SetPath(s *slayers.SCION) error {
	// p.ColibriPathMinimal.InfoField.OrigPayLen = s.PayloadLen
	s.Path, s.PathType = &p.ColibriPathMinimal, colibri.PathType

	// if p.Src != nil {
	// 	s.SrcIA = p.Src.IA
	// }

	// // TODO(juagargi) a problem in the dispatcher prevents the ACK packets from being dispatched
	// // correctly. For now, we need to keep the IP address of the original sender, which is
	// // each one of the colibri services that contact the next colibri service.
	// // s.RawSrcAddr = p.Src.Host
	// // s.SrcAddrType = p.Src.HostType
	// // s.SrcAddrLen = p.Src.HostLen

	// if p.Dst != nil {
	// 	s.DstIA, s.RawDstAddr, s.DstAddrType, s.DstAddrLen = p.Dst.Raw()
	// }

	log.Debug("deleteme snet/path.Colibri.SetPath",
		"path", p.ColibriPathMinimal.String(),
	)

	return nil
}
