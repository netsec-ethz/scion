// Copyright 2024 ETH Zurich
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

package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// The FixedLocalIPTCPDialer behaves the same as the TCP Dialer but allows for setting a local
// IP address. Without this it would not be possible to call IP sensitive endpoints like
// control service drkey.
type FixedLocalIPTCPDialer struct {
	LocalAddr   *net.TCPAddr
	SvcResolver func(addr.SVC) []resolver.Address
}

func (d *FixedLocalIPTCPDialer) Dial(ctx context.Context, dst net.Addr) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		csAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, err
		}
		return net.DialTCP("tcp", d.LocalAddr, csAddr)
	}
	if v, ok := dst.(*snet.SVCAddr); ok {
		targets := d.SvcResolver(v.SVC)
		r := manual.NewBuilderWithScheme("svc")
		r.InitialState(resolver.State{Addresses: targets})
		if len(targets) == 0 {
			return nil, serrors.New("could not resolve")
		}
		return grpc.DialContext(ctx, r.Scheme()+":///"+v.SVC.BaseString(),
			grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
			grpc.WithInsecure(),
			grpc.WithContextDialer(dialer),
			grpc.WithResolvers(r),
			UnaryClientInterceptor(),
			StreamClientInterceptor(),
		)
	} else {
		return grpc.DialContext(ctx, dst.String(),
			grpc.WithInsecure(),
			grpc.WithContextDialer(dialer),
			UnaryClientInterceptor(),
			StreamClientInterceptor(),
		)
	}
}
