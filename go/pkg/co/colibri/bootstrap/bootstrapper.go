package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

type Bootstrapper interface {
	TelescopeFromLocal(ctx context.Context, ases []seg.ASEntry, index int) (*colibri.ReservationLooks, error)
	BootstrapKey(ctx context.Context, segments []*colibri.ReservationLooks) (drkey.Lvl1Key, error)
}

type BootstrapProvider struct {
	localIA      addr.IA
	TopoProvider topology.Provider
	ColProvider  ColibriProvider
	Fetcher      *segfetcher.Fetcher
	Splitter     segfetcher.Splitter
}

type BootstrapError struct {
	MissingIA addr.IA
}

func (e *BootstrapError) Error() string {
	return fmt.Sprintf("Key for intermediate IA missing; ia = %s", e.MissingIA.String())
}

// bootstrapIntermediateKeys checks what Lvl1Keys for intermediate ASes are missing. It tries to fetch them
// via best-effort. If best-effort fails for some intermediate AS (AS-I) it returns an error. Callers might
// check whether keys for AS-I can be securely bootrstaped (i.e. they are in the bootstrap set {BS}
// for the target AS and reuse this method.
func (b *BootstrapProvider) BootstrapKey(ctx context.Context, trip colibri.FullTrip) (*drkey.Lvl1Key, error) {

	logger := log.FromCtx(ctx)
	for _, segR := range trip {
		for _, step := range segR.Path {
			lvl1Meta := drkey.Lvl1Meta{
				SrcIA: step.IA,
				DstIA: b.localIA,
			}
			_, err := b.ColProvider.GetLvl1(ctx, lvl1Meta, util.TimeToSecs(time.Now()))
			if err != nil {
				logger.Error("Key for intermediate IA missing", "ia", step.IA)

				return nil, &BootstrapError{MissingIA: step.IA}
			}
		}
	}
	// At this point we can create a Lvl1Req since we have all intermediate keys to authenticate
	// the payload.
	return b.ColProvider.BootstrapLvl1Key(ctx, trip)
}

func (b *BootstrapProvider) TelescopeFromLocal(ctx context.Context, ases []seg.ASEntry) (*colibri.ReservationLooks, error) {
	return b.telescopeFromLocal(ctx, ases, len(ases)-1)
}

// Base case:
// - Check if a key for AS = ases[1] exist at rest. If not the key is fetched using the
//   NR (neighbor reservation from ases[0] tot ases[1]).
// - A segR from ases[0] up to ases[1] is returned.
// Induction step:
// - There exist a valid segR from ases[0] up to ases[index-1] (previousSeg)
// - Check if a key for AS = ases[index] exist at rest. If not the key is fetched using the
//   previousSegID + NR (neighbor reservation from ases[index-1] tot ases[index]).
// - the previousSeg is freed and a segR from ases[0] up to ases[index] is returned
func (b *BootstrapProvider) telescopeFromLocal(ctx context.Context, ases []seg.ASEntry, index int) (*colibri.ReservationLooks, error) {
	var previousSegID *colibri.ReservationLooks
	var err error
	if index > 1 {
		previousSegID, err = b.telescopeFromLocal(ctx, ases, index-1)
		if err != nil {
			return nil, err
		}
	}
	as := ases[index]
	lvl1Meta := drkey.Lvl1Meta{
		SrcIA: as.Local,
		DstIA: b.localIA,
	}

	nr, err := b.ColProvider.LookupNR(ctx, ases[index-1].Local, ases[index].Local)
	if err != nil {
		return nil, err
	}

	var stichingSeg []*colibri.ReservationLooks
	// Base case
	if index == 1 {
		stichingSeg = []*colibri.ReservationLooks{nr}
	} else {
		stichingSeg = []*colibri.ReservationLooks{previousSegID, nr}
	}

	key, err := b.ColProvider.GetLvl1(ctx, lvl1Meta, util.TimeToSecs(time.Now()))
	if err != nil {
		return nil, err
	}
	if key == nil {
		_, err = b.bootstrapLvl1Key(ctx, b.localIA, stichingSeg)
		if err != nil {
			return nil, err
		}
	}

	if index == 1 {
		return nr, nil
	}
	// Clean previous segment
	if index > 2 {
		if err := b.ColProvider.TearDownSeg(ctx, previousSegID); err != nil {
			return nil, err
		}
	}

	return b.ColProvider.SetupUpSegR(ctx, stichingSeg, ases[index].Local)
}

// bootstrapLvl1Key must receive as an input a valid sequence of segments throughout which it
// will convey the Colibri Lvl1Request. If succesful, the key will be stored in persistance,
// to be used in the future.
func (b *BootstrapProvider) bootstrapLvl1Key(ctx context.Context, dst addr.IA, segments []*colibri.ReservationLooks) (*drkey.Lvl1Key, error) {
	lvl1Key, err := b.ColProvider.BootstrapLvl1Key(ctx, segments)
	if err != nil {
		return nil, err
	}
	err = b.ColProvider.StoreLvl1(ctx, lvl1Key)
	if err != nil {
		return nil, err
	}
	return lvl1Key, nil
}
