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

package drkeyutil

import (
	"context"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dchest/cmac"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ComputeAuthenticators returns the authenticators obtained to apply a MAC function to the
// passed payload.
func ComputeAuthenticators(payload []byte, keys [][]byte) ([][]byte, error) {
	auths := make([][]byte, len(keys))
	for i, k := range keys {
		var err error
		auths[i], err = MAC(payload, k)
		if err != nil {
			return nil, err
		}
	}
	return auths, nil
}

func MAC(payload []byte, key []byte) ([]byte, error) {
	fmt.Printf("deleteme >>>>>>>>>>>> MAC(%s, %s)\n",
		hex.EncodeToString(payload), hex.EncodeToString(key))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.WrapStr("initializing aes cipher", err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.WrapStr("initializing cmac", err)
	}
	_, err = mac.Write(payload)
	if err != nil {
		return nil, serrors.WrapStr("preparing mac", err)
	}
	return mac.Sum(nil), nil
}

// GetLvl2Keys gets the lvl2 keys with the functional options in the arguments.
// Example of use: keys,err := GetLvl2Keys(AS2AS, "colibri", SlowIAs(slow),FastIAs(fast))
func GetLvl2Keys(ctx context.Context, conn DRKeyGetLvl2Keyer,
	keyType drkey.Lvl2KeyType, protocol string,
	options ...keyOptsModifier) ([][]byte, error) {

	opts := &lvl2GetterOptions{
		ctx:       ctx,
		connector: conn,
		keyType:   keyType,
		protocol:  protocol,
	}
	for _, mod := range options {
		mod(opts)
	}
	return getLvl2Keys(opts)
}

func SlowIAs(ias ...addr.IA) keyOptsModifier {
	return func(op *lvl2GetterOptions) {
		op.slowIAs = make([]addr.IA, len(ias))
		copy(op.slowIAs, ias)
	}
}

func SlowHosts(hosts ...addr.HostAddr) keyOptsModifier {
	return func(op *lvl2GetterOptions) {
		op.slowHosts = make([]addr.HostAddr, len(hosts))
		copy(op.slowHosts, hosts)
	}
}

func FastIAs(ias ...addr.IA) keyOptsModifier {
	return func(op *lvl2GetterOptions) {
		op.fastIAs = make([]addr.IA, len(ias))
		copy(op.fastIAs, ias)
	}
}

func FastHosts(hosts ...addr.HostAddr) keyOptsModifier {
	return func(op *lvl2GetterOptions) {
		op.fastHosts = make([]addr.HostAddr, len(hosts))
		copy(op.fastHosts, hosts)
	}
}

type keyOptsModifier func(*lvl2GetterOptions)

type lvl2GetterOptions struct {
	ctx       context.Context
	connector DRKeyGetLvl2Keyer
	keyType   drkey.Lvl2KeyType
	protocol  string
	slowIAs   []addr.IA
	fastIAs   []addr.IA
	slowHosts []addr.HostAddr
	fastHosts []addr.HostAddr
}

func getLvl2Keys(opts *lvl2GetterOptions) ([][]byte, error) {
	// check number of hosts is enough, and concordance with IAs length
	switch opts.keyType {
	case drkey.Host2Host:
		if len(opts.fastHosts) != len(opts.fastIAs) {
			panic("wrong number of hosts/IAs in the fast side")
		}
		fallthrough
	case drkey.AS2Host:
		if len(opts.slowHosts) != len(opts.slowIAs) {
			panic("wrong number of hosts/IAs in the slow side")
		}
		fallthrough
	case drkey.AS2AS:
		if (len(opts.fastIAs) > 1 && len(opts.slowIAs) > 1 &&
			len(opts.fastIAs) != len(opts.slowIAs)) ||
			len(opts.fastIAs) < 1 || len(opts.slowIAs) < 1 {
			panic("specify 1 fast side and n slow, n fast and 1 slow, or n fast and n slow " +
				"(n fast and m slow is not allowed)")
		}
	}
	// check no more hosts than needed
	switch opts.keyType {
	case drkey.AS2AS:
		if len(opts.slowHosts) > 0 {
			panic("no slow hosts allowed for this key type")
		}
		fallthrough
	case drkey.AS2Host:
		if len(opts.fastHosts) > 0 {
			panic("no fast hosts allowed for this key type")
		}
	}

	// functions to extend IAs and hosts:
	extendIAs := func(ias *[]addr.IA, length int) {
		if len(*ias) < length {
			master := (*ias)[0]
			*ias = make([]addr.IA, length)
			for i := 0; i < length; i++ {
				(*ias)[i] = master
			}
		}
	}
	extendHosts := func(hosts *[]addr.HostAddr, length int) {
		if len(*hosts) < length {
			var master addr.HostAddr = addr.HostNone{}
			if len(*hosts) > 0 {
				master = (*hosts)[0]
			}
			*hosts = make([]addr.HostAddr, length)
			for i := 0; i < length; i++ {
				(*hosts)[i] = master
			}
		}
	}
	// we make everything the same length
	length := len(opts.fastIAs)
	if len(opts.slowIAs) > length {
		length = len(opts.slowIAs)
		extendIAs(&opts.fastIAs, length)
	} else {
		extendIAs(&opts.slowIAs, length)
	}
	extendHosts(&opts.slowHosts, length)
	extendHosts(&opts.fastHosts, length)

	metas := make([]drkey.Lvl2Meta, length)
	for i := 0; i < length; i++ {
		metas[i] = drkey.Lvl2Meta{
			KeyType:  opts.keyType,
			Protocol: opts.protocol,
			SrcIA:    opts.fastIAs[i],
			DstIA:    opts.slowIAs[i],
			SrcHost:  opts.fastHosts[i],
			DstHost:  opts.slowHosts[i],
		}
	}

	return getKeys(opts.ctx, opts.connector, time.Now(), metas)
}

type DRKeyGetLvl2Keyer interface {
	DRKeyGetLvl2Key(context.Context, drkey.Lvl2Meta, time.Time) (drkey.Lvl2Key, error)
}

func getKeys(ctx context.Context, conn DRKeyGetLvl2Keyer, valTime time.Time,
	metas []drkey.Lvl2Meta) ([][]byte, error) {
	keys := make([][]byte, len(metas))
	errs := serrors.List{}
	wg := sync.WaitGroup{}
	wg.Add(len(metas))
	for i, meta := range metas {
		i, meta := i, meta
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			k, err := conn.DRKeyGetLvl2Key(ctx, meta, valTime)
			if err != nil {
				errs = append(errs, err)
			}
			keys[i] = k.Key
		}()
	}
	wg.Wait()
	return keys, errs.ToError()
}
