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
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	sgrpc "github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

type traceRouteFlags struct {
	RootFlags
}

func newTraceroute(parent *cobra.Command) *cobra.Command {
	var flags traceRouteFlags

	cmd := &cobra.Command{
		Use:   "traceroute [flags] segR_ID",
		Short: "Traceroute a segment reservation",
		Example: fmt.Sprintf("  %s traceroute --dbgsrv 127.0.0.11:31032 ff00:0:113-00000002",
			parent.CommandPath()),
		Long: "'traceroute' will request the segment reservation identified by ID, " +
			"and send a message to the next AS that appears in it. At every AS the " +
			"segment reservation is retrieved or an error is issued.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return tracerouteCmd(cmd, &flags, args)
		},
	}
	addRootFlags(cmd, &flags.RootFlags)

	return cmd
}

func tracerouteCmd(cmd *cobra.Command, flags *traceRouteFlags, args []string) error {
	cliAddr, err := flags.DebugServer()
	if err != nil {
		return err
	}
	id, err := reservation.IDFromString(args[0])
	if err != nil {
		return serrors.WrapStr("parsing the ID of the segment reservation", err)
	}
	cmd.SilenceUsage = true

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	grpcDialer := sgrpc.TCPDialer{}
	conn, err := grpcDialer.Dial(ctx, cliAddr)
	if err != nil {
		return serrors.WrapStr("dialing to the local debug service", err)
	}
	client := colpb.NewColibriDebugCommandsServiceClient(conn)

	req := &colpb.CmdTracerouteRequest{
		Id:         translate.PBufID(id),
		UseColibri: true,
	}

	return traceroute(func() (*colpb.CmdTracerouteResponse, error) {
		return client.CmdTraceroute(ctx, req)
	})
}

func traceroute(fcn func() (*colpb.CmdTracerouteResponse, error)) error {
	begin := time.Now()
	res, err := fcn()
	if err != nil {
		return err
	}
	if len(res.IaStamp) != len(res.TimeStampFromRequest) ||
		len(res.IaStamp) != len(res.TimeStampAtResponse) {

		return serrors.New("inconsistent response with many sizes")
	}
	if res.ErrorFound != nil {
		msg := fmt.Sprintf("at IA %s: %s\n", addr.IA(res.ErrorFound.Ia), res.ErrorFound.Message)
		if len(res.IaStamp) > 0 {
			msg += fmt.Sprintf("IAs: %v\n", res.IaStamp)
		}
		return serrors.New(msg)
	}

	ias := make([]addr.IA, 0, len(res.IaStamp))
	ts1 := make([]time.Time, 0, len(res.IaStamp))
	ts2 := make([]time.Time, 0, len(res.IaStamp))
	for i := len(res.IaStamp) - 1; i >= 0; i-- {
		ias = append(ias, addr.IA(res.IaStamp[i]))
		ts1 = append(ts1, time.UnixMicro(int64(res.TimeStampFromRequest[i])))
		ts2 = append(ts2, time.UnixMicro(int64(res.TimeStampAtResponse[i])))
	}

	IAColumnWidth := 20

	lastTime := begin
	output := make([]string, 2*len(ias))
	for i := range ias {
		output[i] = fmt.Sprintf("%*s +%s", IAColumnWidth, ias[i], ts1[i].Sub(lastTime))
		lastTime = ts1[i]
	}
	for i := len(ias) - 1; i >= 0; i-- {
		output[i+len(ias)] = fmt.Sprintf("%*s +%s", IAColumnWidth, ias[i], ts2[i].Sub(lastTime))
		lastTime = ts2[i]
	}
	fmt.Printf("%*s %s\n", IAColumnWidth, "step at IA", "time")
	fmt.Printf("%*s %s\n", IAColumnWidth, "________________", "________________")
	fmt.Printf("%*s %s\n", IAColumnWidth, "CLI start", begin.Format(time.StampMicro))
	fmt.Println(strings.Join(output, "\n"))

	return nil
}
