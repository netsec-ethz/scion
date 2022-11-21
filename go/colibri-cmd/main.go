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
	"strings"
	"time"

	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

func main() {

	// TODO(juagargi) make this more amicable and remove panics
	fmt.Println("hi, for now this CLI only supports traceroutinging given a SegR ID")
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		fmt.Println(args)
		panic("use just two arguments: debug_svc_addr segment_id")
	}

	cliAddr, err := net.ResolveTCPAddr("tcp", args[0])
	if err != nil {
		panic(err)
	}

	id, err := reservation.IDFromString(args[1])
	if err != nil {
		panic(err)
	}
	req := &colpb.CmdTracerouteRequest{
		Id:         translate.PBufID(id),
		UseColibri: true,
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	grpcDialer := grpc.TCPDialer{}
	conn, err := grpcDialer.Dial(ctx, cliAddr)
	if err != nil {
		panic(err)
	}
	client := colpb.NewColibriDebugCommandsServiceClient(conn)
	begin := time.Now()
	fmt.Printf("ID is: %s, time at first line relative to checkpoint: %s.  Times shown at each "+
		"step are relative to the previous one\n",
		id.String(), begin.Format(time.StampMicro))
	res, err := client.CmdTraceroute(ctx, req)
	if err != nil {
		panic(err)
	}
	if len(res.IaStamp) != len(res.TimeStampFromRequest) || len(res.IaStamp) != len(res.TimeStampAtResponse) {
		panic("inconsistent response with many sizes")
	}
	if res.ErrorFound != nil {
		fmt.Printf("Error found at IA %s: %s\n", addr.IA(res.ErrorFound.Ia), res.ErrorFound.Message)
		if len(res.IaStamp) > 0 {
			fmt.Printf("IAs: %v\n", res.IaStamp)
		}
		return
	}
	ias := make([]addr.IA, 0, len(res.IaStamp))
	ts1 := make([]time.Time, 0, len(res.IaStamp))
	ts2 := make([]time.Time, 0, len(res.IaStamp))
	for i := len(res.IaStamp) - 1; i >= 0; i-- {
		ias = append(ias, addr.IA(res.IaStamp[i]))
		ts1 = append(ts1, time.UnixMicro(int64(res.TimeStampFromRequest[i])))
		ts2 = append(ts2, time.UnixMicro(int64(res.TimeStampAtResponse[i])))
	}

	lastTime := begin
	output := make([]string, 2*len(ias))
	for i := range ias {
		// output[i] = fmt.Sprintf("%s at %s", ias[len(ias)-i-1], ts1[i].Format(time.StampMicro))
		output[i] = fmt.Sprintf("%s %s", ias[i], ts1[i].Sub(lastTime))
		lastTime = ts1[i]
	}
	for i := len(ias) - 1; i >= 0; i-- {
		// output[i+len(ias)] = fmt.Sprintf("%s at %s", ias[i], ts2[i].Format(time.StampMicro))
		output[i+len(ias)] = fmt.Sprintf("%s %s", ias[i], ts2[i].Sub(lastTime))
		lastTime = ts2[i]
	}

	fmt.Println(strings.Join(output, "\n"))
	// reservation.IDFromRaw()
}
