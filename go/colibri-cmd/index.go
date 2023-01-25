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
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservation/translate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	sgrpc "github.com/scionproto/scion/go/pkg/grpc"
	colpb "github.com/scionproto/scion/go/pkg/proto/colibri"
)

type indexFlags struct {
	RootFlags
	// DebugServerAddr string
	Activate bool
}

func newIndex() *cobra.Command {
	var flags indexFlags

	cmd := &cobra.Command{
		Use:   "index ",
		Short: "Manipulate segment reservation indices",
		Long: "Use this command against the initiator of a SegR to manipulate indices " +
			"of the reservation.",
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(
		indexListCmd(&flags),
		indexCreateCmd(&flags),
		indexActivateCmd(&flags),
		indexCleanupCmd(&flags),
	)

	return cmd
}

func indexListCmd(flags *indexFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list segR_ID",
		Short: "List existing indices for the SegR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return indexList(cmd, flags, args)
		},
	}

	addRootFlags(cmd, &flags.RootFlags)

	return cmd
}

func indexCreateCmd(flags *indexFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new segR_ID",
		Short: "Create and confirm a new index",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return indexCreate(cmd, flags, args)
		},
	}

	addRootFlags(cmd, &flags.RootFlags)
	cmd.PersistentFlags().BoolVar(&flags.Activate, "activate", false, "also activate the index")

	return cmd
}

func indexActivateCmd(flags *indexFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activate segR_ID index_number",
		Short: "Activate an existing index",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return indexActivate(cmd, flags, args)
		},
	}

	addRootFlags(cmd, &flags.RootFlags)

	return cmd
}

func indexCleanupCmd(flags *indexFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup segR_ID index_number",
		Short: "Cleanup an existing index",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return indexCleanup(cmd, flags, args)
		},
	}

	addRootFlags(cmd, &flags.RootFlags)

	return cmd
}

func indexList(cmd *cobra.Command, flags *indexFlags, args []string) error {
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

	// Request to list indices.
	req := &colpb.CmdIndexListRequest{
		Id: translate.PBufID(id),
	}
	res, err := client.CmdIndexList(ctx, req)
	if err != nil {
		return err
	}
	if res.ErrorFound != nil {
		return serrors.New(
			fmt.Sprintf("at IA %s: %s\n", addr.IA(res.ErrorFound.Ia), res.ErrorFound.Message))
	}

	// Print out the list of indices.
	for _, idx := range res.Indices {
		fmt.Printf("%2v: %9s exp: %30s min: %dKbps, max: %dKbps, alloc: %dKbps\n",
			reservation.IndexNumber(idx.Idx),
			segment.IndexState(idx.State),
			util.SecsToTime(idx.Expiration),
			reservation.BWCls(idx.MinBW).ToKbps(),
			reservation.BWCls(idx.MaxBW).ToKbps(),
			reservation.BWCls(idx.AllocBW).ToKbps(),
		)
	}

	return nil
}

func indexCreate(cmd *cobra.Command, flags *indexFlags, args []string) error {
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

	// new index
	req := &colpb.CmdIndexNewRequest{
		Id: translate.PBufID(id),
	}
	res, err := client.CmdIndexNew(ctx, req)
	if err != nil {
		return err
	}
	if res.ErrorFound != nil {
		return serrors.New(
			fmt.Sprintf("at IA %s: %s\n", addr.IA(res.ErrorFound.Ia), res.ErrorFound.Message))
	}
	fmt.Printf("Index with ID %d created.\n", res.Index)

	if flags.Activate {
		return activateIdx(ctx, client, translate.PBufID(id), res.Index)
	}

	return nil
}

func activateIdx(ctx context.Context, client colpb.ColibriDebugCommandsServiceClient,
	segID *colpb.ReservationID, idx uint32) error {

	req := &colpb.CmdIndexActivateRequest{
		Id:    segID,
		Index: idx,
	}
	res, err := client.CmdIndexActivate(ctx, req)
	if err != nil {
		return err
	}
	if res.ErrorFound != nil {
		return serrors.New(
			fmt.Sprintf("at IA %s: %s\n", addr.IA(res.ErrorFound.Ia), res.ErrorFound.Message))
	}
	fmt.Printf("Index with ID %d activated.\n", idx)
	return nil
}

func indexActivate(cmd *cobra.Command, flags *indexFlags, args []string) error {
	return requestWithIndex(cmd, flags, args, activateIdx)
}

func indexCleanup(cmd *cobra.Command, flags *indexFlags, args []string) error {
	cleanupFcn := func(ctx context.Context, client colpb.ColibriDebugCommandsServiceClient,
		segID *colpb.ReservationID, idx uint32) error {

		// new index
		req := &colpb.CmdIndexCleanupRequest{
			Id:    segID,
			Index: idx,
		}
		res, err := client.CmdIndexCleanup(ctx, req)
		if err != nil {
			return err
		}
		if res.ErrorFound != nil {
			return serrors.New(
				fmt.Sprintf("at IA %s: %s\n", addr.IA(res.ErrorFound.Ia), res.ErrorFound.Message))
		}
		fmt.Printf("Index with ID %d cleaned up.\n", idx)
		return nil
	}
	return requestWithIndex(cmd, flags, args, cleanupFcn)
}

func requestWithIndex(cmd *cobra.Command, flags *indexFlags, args []string,
	fcn func(ctx context.Context, client colpb.ColibriDebugCommandsServiceClient,
		segID *colpb.ReservationID, idx uint32) error,
) error {
	cliAddr, err := flags.DebugServer()
	if err != nil {
		return err
	}
	id, err := reservation.IDFromString(args[0])
	if err != nil {
		return serrors.WrapStr("parsing the ID of the segment reservation", err)
	}
	idx, err := strconv.Atoi(args[1])
	if err != nil {
		return serrors.WrapStr("parsing the index number", err)
	}
	if idx < 0 || idx > 15 {
		return serrors.New("index number must be between 0 and 15")
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
	return fcn(ctx, client, translate.PBufID(id), uint32(idx))
}
