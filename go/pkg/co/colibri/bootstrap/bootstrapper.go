package bootstrap

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

type ColibriInterface interface {
	BootstrapLvl1Key(ctx context.Context, dstIA addr.IA, segments []lib_res.ID) (drkey.Lvl1Key, error)

	// SetupUpSegR establishes a SegR from Ato C using segments = {upSegR + NR}.
	// The SegRSetup request travels through a EER established
	// over the same segments.
	//
	// Precondition:
	// - upSegR = {A -> B1 -> Bi -> Bn}
	// - NR = {Bn->C}
	// - We have DRKeys for every on-path AS (included C)
	//
	// Postcondition:
	// - if no error, a SegR from A to C has been allocated.
	SetupUpSegR(ctx context.Context, segs []lib_res.ID) (lib_res.ID, error)
	TearDownSeg(ctx context.Context, seg lib_res.ID) error
	// The internal lookupRes() to other AS must be forward via EER to the remote
	// colibri service
	ListStitchableSegments(ctx context.Context, dst addr.IA) (*colibri.StitchableSegments, error)
	LookupNR(ctx context.Context, transferIA addr.IA, dst addr.IA) (lib_res.ID, error)
}

type DRKeyIface interface {
	// GetLvl1 returns a lvl1 key from persitance. If it is not in persistance
	// it tries to fetch it from the remote CS via best-effort
	GetLvl1(context.Context, drkey.Lvl1Meta, uint32) (*drkey.Lvl1Key, error)
	StoreLvl1(context.Context, drkey.Lvl1Key) error
}

type Bootstrapper struct {
	localIA      addr.IA
	TopoProvider topology.Provider
	ColibriMgr   ColibriInterface
	DRKeyMgr     DRKeyIface
	Fetcher      *segfetcher.Fetcher
	Splitter     segfetcher.Splitter
}

// BootstrapTripTo will return the reservation IDs of a valid trip to dst.
func (b *Bootstrapper) BootstrapTripTo(ctx context.Context, dst addr.IA) ([]lib_res.ID, error) {
	logger := log.FromCtx(ctx)
	reqs, err := b.Splitter.Split(ctx, dst)
	if err != nil {
		return nil, err
	}
	upReqs, coreReqs, downReqs := classifyRequests(reqs)
	var segs segfetcher.Segments
	remoteSegsNeeded := false
	if b.TopoProvider.Get().Core() {

		segs, err = b.Fetcher.Fetch(ctx, coreReqs, false)
		// Even if fetching failed, attempt to create paths.
		if err != nil {
			logger.Debug("Fetching failed, attempting to bootstrap ", "err", err)
		}
		remoteSegsNeeded = len(downReqs) > 0

	} else {
		segs, err = b.Fetcher.Fetch(ctx, upReqs, false)
		// Even if fetching failed, attempt to create paths.
		if err != nil {
			logger.Debug("Fetching failed, attempting to bootstrap ", "err", err)
		}
		remoteSegsNeeded = len(coreReqs) > 0 || len(downReqs) > 0
	}

	// if dst is in the upstream, we return as soon as we have a valid segR to dst:
	var localSegR lib_res.ID
	if !remoteSegsNeeded {
		for _, s := range segs.Segs() {
			localSegR, err = b.telescopeFromLocal(ctx, s.ASEntries, len(s.ASEntries)-1)
			if err == nil {
				return []lib_res.ID{localSegR}, nil
			}
		}
		logger.Debug("all upSegments exhausted")
		return nil, serrors.New("all upSegments exhausted")
	}

	// else (i.e., dst require remote segments)
	// Create SegRs to core bootstrapping upSeg keys (wide-search):
	successfulRsrv := false
	for _, s := range segs.Segs() {
		localSegR, err = b.telescopeFromLocal(ctx, s.ASEntries, len(s.ASEntries)-1)
		if err == nil {
			successfulRsrv = true
		}
		// If timeout retry few times; else if SCMP error should be authenticated
		// more fine error handling could be applied
	}

	if !successfulRsrv {
		logger.Debug("Bootstrapper couldn't create upSegR for any up-segment")
		return nil, serrors.New("Bootstrapper couldn't create upSegR for any up-segment")
	}

	return b.bootstrapKeysRemoteSeg(ctx, dst)

}

// bootstrapKeysRemoteSeg should only be used if dst is not in UpSeg (or coreSegR if localAS is core-AS).
func (b *Bootstrapper) bootstrapKeysRemoteSeg(ctx context.Context, dst addr.IA) ([]lib_res.ID, error) {
	logger := log.FromCtx(ctx)
	// At this point we have at least one valid upSegR
	stichable, err := b.ColibriMgr.ListStitchableSegments(ctx, dst)
	if err != nil {
		serrors.WrapStr("listing stichable segments err", err, "remote as", dst)
	}

	trips := colibri.CombineAll(stichable)
	if len(trips) == 0 {
		return nil, serrors.New("no full trips to destination")
	}

	// XXX(JordiSubira): The bootstrap system needs that we have previously exchanged
	// DRKeys with all intermediate ASes. The reason is that the EER relies on these keys.
	// Therefore, even if we get SegR, we should check that we have access to the
	// needed keys. Otherwise we should retrieve them from the remote AS.
	// In the worst case scenario, intermediate ASes might be under DDoS attack, thus
	// we should leverage the bootstrap system to exchange the keys.

	for _, trip := range trips {

		// Bootstrap keys for every AS in the coreSegR
		err := b.bootstrapIntermediateKeys(ctx, (*trip)[1])
		if err != nil {
			logger.Debug("Couldn't bootstrap keys for the coreSegR")
			continue
		}
		if len(*trip) < 3 {
			stichedSeg := []lib_res.ID{(*trip)[0].Id, (*trip)[1].Id}
			_, err := b.bootstrapLvl1Key(ctx, dst, stichedSeg)
			if err != nil {
				continue
			}
			return stichedSeg, nil
		}

		// Bootstrap keys for every AS in the downSegR
		err = b.bootstrapIntermediateKeys(ctx, (*trip)[2])
		if err != nil {
			logger.Debug("Couldn't bootstrap keys for the downSegR")
			continue
		}
		if err == nil {
			stichedSeg := []lib_res.ID{(*trip)[0].Id, (*trip)[1].Id, (*trip)[2].Id}
			_, err := b.bootstrapLvl1Key(ctx, dst, stichedSeg)
			if err != nil {
				continue
			}
			return stichedSeg, nil
		}

	}

	logger.Debug("all trips exhausted to", "dst", dst)
	return nil, serrors.New("all trips exhausted to", "dst", dst)
}

// bootstrapIntermediateKeys checks what Lvl1Keys for intermediate ASes are missing. It first tries to fetch them,
// via best-effort. If best-effort does not work, it uses the bootstrap system to securely fetch the Lvl1Key.
// This inducitve mechanism can be used because by assumption there exist a path whose ASes are part of the
// bootstrap set {BS} for the target AS (i.e. the segR.LastHop). For the definition of BS please refer to
// {report}.
func (b *Bootstrapper) bootstrapIntermediateKeys(ctx context.Context, segR *colibri.ReservationLooks) error {
	logger := log.FromCtx(ctx)
	for i, step := range segR.Path {
		lvl1Meta := drkey.Lvl1Meta{
			ProtoId: drkey.COLIBRI,
			SrcIA:   step.IA,
			DstIA:   b.localIA,
		}
		key, err := b.DRKeyMgr.GetLvl1(ctx, lvl1Meta, util.TimeToSecs(time.Now()))
		if key != nil {
			continue
		}
		if i == 0 {
			// Keys for transfer AS must have been established beforehand as the last hop of upSegR, or
			// the last hop of coreSegR. If the DRKey for this AS is not locally stored we move to the next
			// segment.
			return serrors.New("transfer AS key is not at rest", "as", step.IA)
		}
		// JordiSubira(TODO): Check kind of error, if it is error at fetching try bootstrap fetching

		_, err = b.bootstrapKeysRemoteSeg(ctx, step.IA)
		if err != nil {
			logger.Error("We cannot bootstrap to", "IA", step.IA)
			return err
		}
	}
	// All intermediate keys bootstrapped
	return nil
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
func (b *Bootstrapper) telescopeFromLocal(ctx context.Context, ases []seg.ASEntry, index int) (lib_res.ID, error) {
	var previousSegID lib_res.ID
	var err error
	if index > 1 {
		previousSegID, err = b.telescopeFromLocal(ctx, ases, index-1)
		if err != nil {
			return lib_res.ID{}, err
		}
	}
	as := ases[index]
	lvl1Meta := drkey.Lvl1Meta{
		ProtoId: drkey.COLIBRI,
		SrcIA:   as.Local,
		DstIA:   b.localIA,
	}

	nr, err := b.ColibriMgr.LookupNR(ctx, ases[index-1].Local, ases[index].Local)
	if err != nil {
		return lib_res.ID{}, err
	}

	var stichingSeg []lib_res.ID
	// Base case
	if index == 1 {
		stichingSeg = []lib_res.ID{nr}
	} else {
		stichingSeg = []lib_res.ID{previousSegID, nr}
	}

	key, err := b.DRKeyMgr.GetLvl1(ctx, lvl1Meta, util.TimeToSecs(time.Now()))
	if err != nil {
		return lib_res.ID{}, err
	}
	if key == nil {
		_, err = b.bootstrapLvl1Key(ctx, b.localIA, stichingSeg)
		if err != nil {
			return lib_res.ID{}, err
		}
	}

	// Clean previous segment
	if err := b.ColibriMgr.TearDownSeg(ctx, previousSegID); err != nil {
		return lib_res.ID{}, err
	}

	return b.ColibriMgr.SetupUpSegR(ctx, stichingSeg)
}

// bootstrapLvl1Key must receive as an input a valid sequence of segments throughout which it
// will convey the Colibri Lvl1Request. If succesful, the key will be stored in persistance,
// to be used in the future.
func (b *Bootstrapper) bootstrapLvl1Key(ctx context.Context, dst addr.IA, segments []lib_res.ID) (drkey.Lvl1Key, error) {
	lvl1Key, err := b.ColibriMgr.BootstrapLvl1Key(ctx, b.localIA, segments)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	b.DRKeyMgr.StoreLvl1(ctx, lvl1Key)
	if err != nil {
		return drkey.Lvl1Key{}, err
	}
	return lvl1Key, nil
}

func classifyRequests(requests segfetcher.Requests) (ups, cores, downs segfetcher.Requests) {
	for _, req := range requests {
		switch req.SegType {
		case seg.TypeUp:
			ups = append(ups, req)
		case seg.TypeCore:
			cores = append(cores, req)
		case seg.TypeDown:
			downs = append(downs, req)
		}

	}
	return ups, cores, downs
}
