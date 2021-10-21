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

package colibrisubcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Result struct {
	Destination       addr.IA
	Stitchables       *colibri.StitchableSegments
	Trips             []*colibri.FullTrip
	ComputedFullTrips int
}

func (r Result) Human(w io.Writer, colored bool) {
	cs := DefaultColorScheme(!colored)

	fmt.Fprintln(w, cs.Header.Sprint("Stitchable Segments:"))
	humanSegLooks(w, cs, cs.Type.Sprint("   up"), r.Stitchables.Up)
	humanSegLooks(w, cs, cs.Type.Sprint(" core"), r.Stitchables.Core)
	humanSegLooks(w, cs, cs.Type.Sprint(" down"), r.Stitchables.Down)

	fmt.Fprintln(w, cs.Header.Sprint("Full Trips:"))
	humanFulTrips(w, cs, r.Trips)
}

func (r Result) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func Run(ctx context.Context, dst addr.IA, cfg Config) (*Result, error) {
	sdConn, err := daemon.NewService(cfg.Daemon).Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("connecting to the SCION Daemon", err, "addr", cfg.Daemon)
	}

	stSegs, err := sdConn.ColibriListRsvs(ctx, dst)
	if err != nil {
		return nil, serrors.WrapStr("listing segment reservations", err)
	}
	fullTrips := colibri.CombineAll(stSegs)
	computedFullTripCount := len(fullTrips)
	if cfg.MaxFullTrips < len(fullTrips) {
		fullTrips = fullTrips[:cfg.MaxFullTrips]
	}
	// after combination, trim the stitchable segments for displaying
	limitNumberOfStitchableSegs(cfg.MaxStitRsvs, stSegs)

	return &Result{
		Destination:       dst,
		Stitchables:       stSegs,
		Trips:             fullTrips,
		ComputedFullTrips: computedFullTripCount,
	}, nil
}

func limitNumberOfStitchableSegs(max int, stSegs *colibri.StitchableSegments) {
	limit := func(m int, looks *[]*colibri.ReservationLooks) {
		if m < len(*looks) {
			*looks = (*looks)[:m]
		}
	}
	limit(max, &stSegs.Up)
	limit(max, &stSegs.Core)
	limit(max, &stSegs.Down)
}

func humanSegLooks(w io.Writer, cs ColorScheme, ptype string, looks []*colibri.ReservationLooks) {
	idxWidth := int(math.Log10(float64(len(looks)))) + 1
	for i, look := range looks {
		fmt.Fprintf(w, "[%*d] %6s %s\n", idxWidth, i, ptype, humanSegLook(cs, look))
	}
}

func humanSegLook(cs ColorScheme, look *colibri.ReservationLooks) string {
	return strings.Join(cs.KeyValues(
		"ID", look.Id.String(),
		"bw", fmt.Sprintf("%3d", look.AllocBW),
		"steps", humanPathSteps(cs, look.PathSteps),
		"Expiration", humanStatus(cs, look.ExpirationTime.UTC()),
	), " ")
}

func humanPathSteps(cs ColorScheme, steps []reservation.PathStep) string {
	if len(steps) < 2 {
		panic(fmt.Sprintf("length of reservation (%d) is wrong, with steps: %v", len(steps), steps))
	}
	strs := make([]string, len(steps))
	strs[0] = fmt.Sprintf("%s %s", cs.Values.Sprint(steps[0].IA), cs.Intf.Sprint(steps[0].Egress))
	for i := 1; i < len(steps)-1; i++ {
		step := steps[i]
		strs[i] = fmt.Sprintf("%s %s %s",
			cs.Intf.Sprint(step.Ingress),
			cs.Values.Sprint(step.IA),
			cs.Intf.Sprint(step.Egress))
	}
	strs[len(strs)-1] = fmt.Sprintf("%s %s", cs.Intf.Sprint(steps[len(steps)-1].Ingress),
		cs.Values.Sprint(steps[len(steps)-1].IA))
	return strings.Join(strs, cs.Link.Sprint(">"))
}

func humanStatus(cs ColorScheme, expTime time.Time) string {
	t := expTime.Format(time.Stamp)
	if time.Now().After(expTime) {
		return cs.Bad.Sprint(t)
	}
	return cs.Good.Sprint(t)
}

func humanFulTrips(w io.Writer, cs ColorScheme, fullTrips []*colibri.FullTrip) {
	idxWidth := int(math.Log10(float64(len(fullTrips)))) + 1
	for i, ft := range fullTrips {
		fmt.Fprintf(w, "[%*d] %s\n", idxWidth, i, humanFullTrip(cs, *ft))
	}
}

func humanFullTrip(cs ColorScheme, ft colibri.FullTrip) string {
	stitches := make([]string, len(ft))
	for i, s := range ft {
		stitches[i] = fmt.Sprintf("%s (ID %s)--> %s",
			s.SrcIA,
			cs.Intf.Sprint(s.Id),
			s.DstIA)
	}
	return strings.Join(cs.KeyValues(
		"bw", fmt.Sprintf("%3d", ft.AllocBW()),
		"Expiration:", humanStatus(cs, ft.ExpirationTime()),
		"Stitches", strings.Join(stitches, cs.Link.Sprint(" >>> ")),
		"hops", fmt.Sprint(ft.NumberOfASes()),
	), " ")
}
