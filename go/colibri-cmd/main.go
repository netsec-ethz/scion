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

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

func main() {

	// TODO(juagargi) make this more amicable and remove panics
	fmt.Println("hi, for now this CLI only supports echoing given a SegR ID")
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		fmt.Println(args)
		panic("use just two arguments: debug_svc_addr segment_id")
	}

	addr, err := net.ResolveTCPAddr("tcp", args[0])
	if err != nil {
		panic(err)
	}

	id, err := reservation.IDFromString(args[1])
	if err != nil {
		panic(err)
	}
	req := &colpb.EchoWithSegrRequest{
		Id: translate.PBufID(id),
	}

	fmt.Printf("ID is: %s\n", id.String())

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	grpcDialer := grpc.TCPDialer{}
	conn, err := grpcDialer.Dial(ctx, addr)
	if err != nil {
		panic(err)
	}
	client := colpb.NewColibriDebugCommandsClient(conn)
	res, err := client.EchoWithSegr(ctx, req)
	if err != nil {
		panic(err)
	}
	fmt.Printf("error in response? %v, message: %s\n", res.Error, res.Message)
	// reservation.IDFromRaw()
}
