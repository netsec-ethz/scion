// Copyright 2021 ETH Zurich
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

// Package fake provides fake DRKeys for testing.
// Note: not all key types are currently supported, simply because there is
// currently no need.
package fake

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Keyer allows to obtain fake keys with the same interface as the daemon.
type Keyer struct {
	LocalIA addr.IA
	LocalIP net.IP
}

func (k Keyer) DRKeyGetASHostKey(_ context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	if meta.DstIA != k.LocalIA {
		return drkey.ASHostKey{}, serrors.New("invalid request, req.dstIA != localIA",
			"req.dstIA", meta.DstIA, "localIA", k.LocalIA)
	}
	dstIP := net.ParseIP(meta.DstHost)
	if !k.LocalIP.Equal(dstIP) {
		return drkey.ASHostKey{}, serrors.New("invalid request, req.dstHost != local IP",
			"req.dstHost", meta.DstHost, "local IP", k.LocalIP)
	}
	return ASHost(meta), nil
}

// Epoch returns the issuer's epoch containing the validity timestamp.
// Note that different issuers can use different epochs (e.g. different lengths
// or different start time).
func Epoch(issuer addr.IA, validity time.Time) drkey.Epoch {
	r := rand.New(rand.NewSource(int64(issuer)))
	epochLen := time.Duration(2+r.Intn(8)) * time.Second // very short epochs, 2-10s for testing

	epochStart := validity.Truncate(epochLen)
	epochEnd := epochStart.Add(epochLen)
	return drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: epochStart,
			NotAfter:  epochEnd,
		},
	}
}

// Lvl1Key builds a fake Level1 key.
func Lvl1Key(meta drkey.Lvl1Meta) drkey.Lvl1Key {
	epoch := Epoch(meta.SrcIA, meta.Validity)

	const keyTypeLvl1 uint8 = 0
	var key drkey.Key
	key[0] = keyTypeLvl1
	key[1] = byte(epoch.NotBefore.Second())
	key[2] = byte(meta.ProtoId) // truncated
	// ISD truncated to 1 byte, AS truncated to 2 bytes.
	// More than enough to represent the AS IDs usuually used in testing.
	key[3] = byte(meta.SrcIA.ISD())
	binary.BigEndian.PutUint16(key[4:], uint16(meta.SrcIA.AS()))
	key[6] = byte(meta.DstIA.ISD())
	binary.BigEndian.PutUint16(key[7:], uint16(meta.DstIA.AS()))

	return drkey.Lvl1Key{
		ProtoId: meta.ProtoId,
		Epoch:   epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Key:     key,
	}
}

// Lvl1Key builds a fake ASHost key.
// This is _not_ properly derived from the fake Lvl1Key().
func ASHost(meta drkey.ASHostMeta) drkey.ASHostKey {
	epoch := Epoch(meta.SrcIA, meta.Validity)

	const keyTypeASHost uint8 = 2
	var key drkey.Key
	key[0] = keyTypeASHost
	key[1] = byte(epoch.NotBefore.Second())
	key[2] = byte(meta.ProtoId) // truncated
	// ISD truncated to 1 byte, AS truncated to 2 bytes.
	// More than enough to represent the AS IDs usuually used in testing.
	key[3] = byte(meta.SrcIA.ISD())
	binary.BigEndian.PutUint16(key[4:], uint16(meta.SrcIA.AS()))
	key[6] = byte(meta.DstIA.ISD())
	binary.BigEndian.PutUint16(key[7:], uint16(meta.DstIA.AS()))

	ip := net.ParseIP(meta.DstHost)
	key[9] = byte(len(ip))
	copy(key[10:], ip[:])

	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		DstHost: meta.DstHost,
		Key:     key,
	}
}
