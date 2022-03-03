package bootstrap

import (
	"context"
	"database/sql"
	"time"

	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/grpc"
)

// DRKeyProvider retrieves DRKeys, e.g. from persistence and/or fetching
// via best-effort
type DRKeyProvider interface {
	GetKey(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (*drkey.Lvl2Key, error)
}

// SegProvider provides upstream segment to core for non-core ASes
// and core segments to core ASes
type SegProvider interface {
	FirstSegIAs(ctx context.Context, dst addr.IA) ([][]addr.IA, error)
}

// Pather provides paths given a destination IA.
type Pather interface {
	Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error)
}

type segProvider struct {
	pather Pather
}

func NewSegProvider(pather Pather) *segProvider {
	return &segProvider{
		pather: pather,
	}
}

// FirstSegIAs returns a 2-dimension slice that contains the AS of the initial path segment
// (up segement or core segment) to the destination.
func (p *segProvider) FirstSegIAs(ctx context.Context, dst addr.IA) ([][]addr.IA, error) {
	logger := log.FromCtx(ctx)
	paths, err := p.pather.Paths(ctx, dst)
	if err != nil {
		return nil, serrors.WrapStr("requesting paths to dst", err)
	}

	upSegs := [][]addr.IA{}
	for _, path := range paths {
		ases, err := upstreamIAs(ctx, path)
		if err != nil {
			logger.Debug("Error extracting upstream AS list", "err", err)
			continue
		}
		upSegs = append(upSegs, ases)
	}
	return upSegs, nil
}

func upstreamIAs(ctx context.Context, path snet.Path) ([]addr.IA, error) {
	var dp scion.Decoded
	err := dp.DecodeFromBytes(path.Path().Raw)
	if err != nil {
		return nil, err
	}
	upSegLen := int(dp.PathMeta.SegLen[0])
	interfaces := path.Metadata().Interfaces

	ias := make([]addr.IA, upSegLen)
	if upSegLen > 0 {
		ias[0] = interfaces[0].IA
	}
	for i := 1; i < upSegLen; i++ {
		ias[i] = interfaces[i*2-1].IA
	}
	return ias, nil
}

type DRKeyBootstrapper struct {
	LocalIA      addr.IA
	LocalHost    addr.HostAddr
	Provider     DRKeyProvider
	ColStore     reservationstorage.Store
	Bootstrapper Bootstrapper
	SegProvider  SegProvider
}

// GetKey uses the bootstrap mechanism to fetch a key from a remote IA (embedded in meta.SrcIA)
func (e *DRKeyBootstrapper) GetKey(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (*drkey.Lvl2Key, error) {
	// First try using best-effort
	log.FromCtx(ctx).Debug("Fetching key via persistence/best-effort", "targetIA", meta.SrcIA)
	key, err := e.Provider.GetKey(ctx, meta, valTime)
	if err != nil {
		log.FromCtx(ctx).Debug("Best effort did not work, trying bootstrap mechanism",
			"targetIA", meta.SrcIA, "err", err)
		return e.simpleExploration(ctx, meta, valTime)
	}
	return key, nil
}

func (e *DRKeyBootstrapper) simpleExploration(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (*drkey.Lvl2Key, error) {
	logger := log.FromCtx(ctx)

	upSegs, err := e.SegProvider.FirstSegIAs(ctx, meta.SrcIA)
	if err != nil {
		return nil, err
	}

	for _, ias := range upSegs {
		lastUpHop := ias[len(ias)-1]
		logger.Debug("Listing reservations from source", "srcIA", e.LocalIA, "coreIA", lastUpHop)
		reservations, err := e.ColStore.ListReservations(ctx, lastUpHop, reservation.UpPath)
		if err != nil || reservations == nil || len(reservations) <= 0 {
			logger.Debug("No reservations from source, trying telescope method",
				"srcIA", e.LocalIA, "coreIA", lastUpHop)
			_, err := e.Bootstrapper.TelescopeUpstream(ctx, ias)
			if err != nil {
				logger.Debug("Error telescoping, we try other upSeg", "err", err)
				continue
			}
			logger.Debug("Telescope successful for",
				"srcIA", e.LocalIA, "coreIA", lastUpHop)
		}

		// If dstIA is in upstream we must have a valid key at this point
		if lastUpHop == meta.SrcIA {
			return e.Provider.GetKey(ctx, meta, valTime)
		}
	}

	// Now we have established a SegR to the dst or to core

	// First we reach remote core ASes.

	// XXX(JordiSubira): Lookup request should be conveyed over EER to achieve
	// stronger guarantees. Similar to what is done in the Bootstrapper.sendSetupUpSegR
	logger.Debug("Listing stichable from source", "srcIA", e.LocalIA, "coreISD", meta.SrcIA.I)
	remoteCore := addr.IA{I: meta.SrcIA.I, A: 0}
	stichableCore, err := e.ColStore.ListStitchableSegments(ctx, remoteCore)
	if err != nil {
		serrors.WrapStr("listing stichable segments err", err, "remote as", meta.DstIA)
	}
	tripsCore := colibri.CombineAll(stichableCore)
	for _, trip := range tripsCore {
		_, err := e.bootstrapKey(ctx, *trip, valTime)
		if err != nil {
			logger.Debug("Error bootstrapping core trip", "err", err)
			continue
		}
		logger.Debug("Key fetched", "coreAS", trip.DstIA().String())
	}

	// XXX(JordiSubira): Lookup request should be conveyed over EER to achieve
	// stronger guarantees. Similar to what is done in the Bootstrapper.sendSetupUpSegR
	logger.Debug("Listing stichable from source", "srcIA", e.LocalIA, "dstIA", meta.SrcIA)
	stichable, err := e.ColStore.ListStitchableSegments(ctx, meta.SrcIA)
	if err != nil {
		serrors.WrapStr("listing stichable segments err", err, "remote as", meta.DstIA)
	}

	trips := colibri.CombineAll(stichable)
	for _, trip := range trips {
		key, err := e.bootstrapKey(ctx, *trip, valTime)
		if err != nil {
			logger.Debug("Error bootstrapping, we try other trip", "err", err)
			continue
		}
		logger.Debug("Key fetched", "targetIA", meta.SrcIA)
		return key, nil
	}
	logger.Debug("No trip worked for the current upSeg",
		"srcIA", e.LocalIA, "dstIA", meta.SrcIA, "upSeg", upSegs)
	return nil, serrors.New("Unable to bootstrap key using any available path")
}

func (e *DRKeyBootstrapper) bootstrapKey(ctx context.Context, trip colibri.FullTrip,
	valTime time.Time) (*drkey.Lvl2Key, error) {
	if len(trip) < 1 {
		return nil, serrors.New("Invalid provided trip to bootstrap a DRKey")
	}
	lastSeg := trip[len(trip)-1].Path
	lastStep := lastSeg[len(lastSeg)-1]

	logger := log.FromCtx(ctx)
	logger.Debug("Starting to search for drkey in trip", "trip", trip.String())

	for _, segR := range trip {
		for i, step := range segR.Path {
			if step != lastStep && i > 0 {
				lvl2Meta := drkey.Lvl2Meta{
					SrcIA:   step.IA,
					DstIA:   e.LocalIA,
					DstHost: e.LocalHost,
				}
				// In the general case, this keys should be in persistence
				// or fetched using best-effort.
				_, err := e.GetKey(ctx, lvl2Meta, valTime)
				if err != nil {
					return nil, serrors.Wrap(ErrMissingKey, err)
				}
			}
		}
	}
	lvl2Meta := drkey.Lvl2Meta{
		SrcIA:   lastStep.IA,
		DstIA:   e.LocalIA,
		DstHost: e.LocalHost,
	}

	log.FromCtx(ctx).Debug("Fetching key via persistence/best-effort", "targetIA", lvl2Meta.SrcIA)
	key, err := e.Provider.GetKey(ctx, lvl2Meta, valTime)
	// At this point we can create a request since we have all intermediate keys to authenticate
	// the payload.
	if err != nil {
		log.FromCtx(ctx).Debug("All intermediate keys fetched, sending DRKey request over trip",
			"dstIA", trip.DstIA(), "trip", trip.String())
		return e.Bootstrapper.SendDRKeyReq(ctx, trip, valTime)
	}
	return key, nil
}

type BestEffortProvider struct {
	DB      drkey.Lvl2DB
	Fetcher grpc.DRKeyFetcher
}

// GetKey tries to obtain the DRKey for the remote using conventional methods
func (p *BestEffortProvider) GetKey(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (*drkey.Lvl2Key, error) {
	// TODO(JordiSubira): First try DB lookup
	return p.Fetcher.GetDRKeyLvl2(ctx, meta, valTime)
}

// FakeProvider simulates fetching keys from remote by
// mapping them at rest beforehand
type FakeProvider struct {
	DB FakeDB
}

func (p *FakeProvider) GetKey(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (*drkey.Lvl2Key, error) {

	key, err := p.DB.GetLvl2Key(ctx, meta, util.TimeToSecs(valTime))
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// FakeDB keeps an in-memory storage
type FakeDB struct {
	storage map[addr.IA]drkey.Lvl2Key
}

func NewFakeDB(localIA addr.IA, localHost addr.HostAddr, dstList []addr.IA) FakeDB {
	m := map[addr.IA]drkey.Lvl2Key{}
	for _, ia := range dstList {
		m[ia] = fakeKey(ia, localIA, localHost)
	}
	return FakeDB{
		storage: m,
	}
}

func (db FakeDB) GetLvl2Key(ctx context.Context,
	meta drkey.Lvl2Meta, _ uint32) (drkey.Lvl2Key, error) {
	key, ok := db.storage[meta.SrcIA]
	if ok {
		return key, nil
	}
	return drkey.Lvl2Key{}, sql.ErrNoRows
}
func (db FakeDB) InsertLvl2Key(ctx context.Context, key drkey.Lvl2Key) error {
	db.storage[key.SrcIA] = key
	return nil
}
func (db FakeDB) RemoveOutdatedLvl2Keys(ctx context.Context, cutoff uint32) (int64, error) {
	panic("not implemented")
}
func (db FakeDB) Close() error {
	panic("not implemented")
}
func (db FakeDB) SetMaxOpenConns(maxOpenConns int) {
	panic("not implemented")
}
func (db FakeDB) SetMaxIdleConns(maxIdleConns int) {
	panic("not implemented")
}
