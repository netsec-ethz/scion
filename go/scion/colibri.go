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

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/flag"
	colsubcmd "github.com/scionproto/scion/go/pkg/scioncolibrisubcmd"
)

func newColibri(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		timeout  time.Duration
		cfg      colsubcmd.Config
		json     bool
		logLevel string
		noColor  bool
		tracer   string
	}

	var cmd = &cobra.Command{
		Use:     "colibri",
		Short:   "Display segment reservations from local to destination AS",
		Aliases: []string{"co"},
		Args:    cobra.ExactArgs(1),
		Example: fmt.Sprintf(`  %[1]s colibri 1-ff00:0:110
  %[1]s colibri 1-ff00:0:110 --json`,
			pather.CommandPath()),
		Long: `'colibri' lists available segment reservations between the local
and the specified SCION ASes.

'colibri' can be instructed to output the paths as json using the the --json flag.

If no segment reservation is found and json output is not enabled,
colibri will exit with code 1.
On other errors, colibri will exit with code 2.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dst, err := addr.ParseIA(args[0])
			if err != nil {
				return serrors.WrapStr("invalid destination ISD-AS", err)
			}
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			closer, err := setupTracer("colibri", flags.tracer)
			if err != nil {
				return serrors.WrapStr("setting up tracing", err)
			}
			defer closer()

			cmd.SilenceUsage = true

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}

			flags.cfg.Daemon = envFlags.Daemon()
			log.Debug("Resolved SCION environment flags",
				"daemon", flags.cfg.Daemon,
			)

			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			span.SetTag("dst.isd_as", dst)
			defer span.Finish()

			ctx, cancel := context.WithTimeout(traceCtx, flags.timeout)
			defer cancel()
			res, err := colsubcmd.Run(ctx, dst, flags.cfg)
			if err != nil {
				return err
			}

			if flags.json {
				return res.JSON(os.Stdout)
			}
			if res.ComputedFullTrips == 0 {
				return app.WithExitCode(serrors.New("no reservation found"), 1)
			}
			res.Human(os.Stdout, !flags.noColor)

			return nil
		},
	}

	envFlags.Register(cmd.Flags())
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Timeout")
	cmd.Flags().IntVarP(&flags.cfg.MaxStitRsvs, "maxstitches", "t", 10,
		"Maximum number of segment stitches that are displayed")
	cmd.Flags().IntVarP(&flags.cfg.MaxFullTrips, "maxtrips", "m", 10,
		"Maximum number of full trips that are displayed")
	cmd.Flags().BoolVarP(&flags.json, "json", "j", false,
		"Write the output as machine readable json")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	return cmd
}
