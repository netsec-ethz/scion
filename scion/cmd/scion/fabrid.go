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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/tracing"
)

func newFabrid(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		timeout  time.Duration
		logLevel string
		noColor  bool
		tracer   string
		format   string
	}

	var cmd = &cobra.Command{
		Use:   "fabrid identifier [remote_as]",
		Short: "Display FABRID policy information",
		Args:  cobra.RangeArgs(1, 2),
		Example: fmt.Sprintf(`  %[1]s fabrid G1001
  %[1]s fabrid L1101 1-ff00:0:110
  %[1]s fabrid L1101 1-ff00:0:110 --log.level debug'`, pather.CommandPath()),
		Long: `'fabrid' fetches the description of a global or local FABRID policy.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args[0]) < 2 {
				return serrors.New("Invalid identifier format", "identifier", args[0])
			}
			cs := path.DefaultColorScheme(flags.noColor)
			identifierPrefix := args[0][0]
			var isLocal bool
			switch identifierPrefix {
			case 'L':
				isLocal = true
			case 'G':
				isLocal = false
			default:
				return serrors.New("invalid identifier prefix", "prefix", string(identifierPrefix))
			}

			identifier, err := strconv.ParseUint(args[0][1:], 10, 32)
			if err != nil {
				return serrors.New("invalid identifier format", "identifier", args[0])
			}

			if isLocal && len(args) == 1 {
				return serrors.New("missing destination ISD-AS for local policy")
			}
			var dst addr.IA
			if len(args) > 1 {
				if !isLocal {
					return serrors.New(
						"unexpected argument. Global policies require no destination AS.")
				}
				dst, err = addr.ParseIA(args[1])
				if err != nil {
					return serrors.WrapStr("invalid destination ISD-AS", err)
				}
			}
			if err = app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			closer, err := setupTracer("fabrid", flags.tracer)
			if err != nil {
				return serrors.WrapStr("setting up tracing", err)
			}
			defer closer()

			cmd.SilenceUsage = true

			if err = envFlags.LoadExternalVars(); err != nil {
				return err
			}

			daemonAddr := envFlags.Daemon()

			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			defer span.Finish()
			span.SetTag("dst.isd_as", dst)

			ctx, cancel := context.WithTimeout(traceCtx, flags.timeout)
			defer cancel()

			var description string
			daemonService := &daemon.Service{
				Address: daemonAddr,
			}
			sdConn, err := daemonService.Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to the SCION Daemon", err, "addr", daemonAddr)
			}
			defer sdConn.Close()

			description, err = sdConn.PolicyDescription(ctx, isLocal, uint32(identifier), &dst)
			if err != nil {
				return serrors.WrapStr("retrieving description from the SCION Daemon", err)
			}
			// Format and output the description based on the specified format
			// Create a struct with the required fields and marshal it to the specified format
			// for json and yaml:
			output := struct {
				Identifier  uint32
				Local       bool
				Description string
			}{uint32(identifier), isLocal, description}
			switch flags.format {
			case "human":
				if isLocal {
					fmt.Printf("Policy %s@%s\n",
						cs.LocalPolicy.Sprintf("L%d", identifier),
						cs.Link.Sprintf("%s", dst))
				} else {
					fmt.Printf("Policy %s\n",
						cs.GlobalPolicy.Sprintf("G%d", identifier))
				}
				fmt.Printf("  %s\n", description)
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(output)
			case "yaml":
				enc := yaml.NewEncoder(os.Stdout)
				return enc.Encode(output)
			}
			// Output the description
			return nil
		},
	}

	envFlags.Register(cmd.Flags())
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Timeout")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	return cmd
}
