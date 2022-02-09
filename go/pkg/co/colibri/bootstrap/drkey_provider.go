package bootstrap

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/grpc"
)

type DRKeyProvider interface {
	GetKey(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (*drkey.Lvl2Key, error)
}

type UpSegProvider interface {
	UpSegIAs(ctx context.Context, dst addr.IA) ([][]addr.IA, error)
}

type Pather interface {
	Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error)
}

type upSegProvider struct {
	pather Pather
}

func (u *upSegProvider) UpSegIAs(ctx context.Context, dst addr.IA) ([][]addr.IA, error) {
	logger := log.FromCtx(ctx)
	paths, err := u.pather.Paths(ctx, dst)
	if err != nil {
		return nil, serrors.WrapStr("requesting paths to dst", err)
	}
	upSegs := [][]addr.IA{}
	for _, path := range paths {
		ases, err := upstreamIAs(path)
		if err != nil {
			logger.Debug("Error extracting upstream AS list", "err", err)
			continue
		}
		upSegs = append(upSegs, ases)
	}
	return upSegs, nil
}

func upstreamIAs(path snet.Path) ([]addr.IA, error) {
	var dp scion.Decoded
	err := dp.DecodeFromBytes(path.Path().Raw)
	if err != nil {
		return nil, err
	}
	upSegLen := int(dp.PathMeta.SegLen[0])
	interfaces := path.Metadata().Interfaces
	ias := make([]addr.IA, upSegLen)
	for i := 0; i < upSegLen; i++ {
		ias[i] = interfaces[i].IA
	}
	return ias, nil
}

type DRKeyBootstrapper struct {
	LocalIA      addr.IA
	localHost    addr.HostAddr
	Provider     DRKeyProvider
	ColStore     reservationstorage.Store
	Bootstrapper Bootstrapper
	SegProvider  UpSegProvider
}

func (e *DRKeyBootstrapper) GetKey(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (*drkey.Lvl2Key, error) {
	// First try using best-effort
	key, err := e.Provider.GetKey(ctx, meta, valTime)
	if err != nil {
		log.FromCtx(ctx).Debug("Best effort did not work, trying bootstrap mechanism", "err", err)
		return e.simpleExploration(ctx, meta, valTime)
	}
	return key, nil
}

func (e *DRKeyBootstrapper) simpleExploration(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (*drkey.Lvl2Key, error) {
	logger := log.FromCtx(ctx)

	upSegs, err := e.SegProvider.UpSegIAs(ctx, meta.SrcIA)
	if err != nil {
		return nil, err
	}

	for _, ias := range upSegs {
		lastUpHop := ias[len(ias)-1]
		reservations, err := e.ColStore.ListStitchableSegments(ctx, lastUpHop)
		if err != nil || reservations == nil || len(reservations.Up) <= 0 {
			_, err := e.Bootstrapper.TelescopeUpstream(ctx, ias)
			if err != nil {
				logger.Debug("Error telescoping, we try other upSeg", "err", err)
				continue
			}
		}

		// If dstIA is in upstream we must have a valid key at this point
		if lastUpHop == meta.SrcIA {
			return e.Provider.GetKey(ctx, meta, valTime)
		}

		// Now we have established a SegR to the dst or to core

		// XXX(JordiSubira): Lookup request should be conveyed over EER to achieve
		// stronger guarantees. Similar to what is done in the Bootstrapper.SendDRKeyReq
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
			return key, nil
		}
	}
	return nil, serrors.New("Unable to bootstrap key using any available path")
}

func (e *DRKeyBootstrapper) bootstrapKey(ctx context.Context, trip colibri.FullTrip,
	valTime time.Time) (*drkey.Lvl2Key, error) {
	if len(trip) < 1 {
		return nil, serrors.New("Invalid provided trip to bootstrap a DRKey")
	}
	lastSeg := trip[len(trip)-1].Path
	lastStep := lastSeg[len(lastSeg)-1]

	for _, segR := range trip {
		for i, step := range segR.Path {
			if step != lastStep && i > 0 {
				lvl2Meta := drkey.Lvl2Meta{
					SrcIA:   step.IA,
					DstIA:   e.LocalIA,
					DstHost: e.localHost,
				}
				_, err := e.GetKey(ctx, lvl2Meta, valTime)
				if err != nil {
					return nil, serrors.Wrap(ErrMissingKey, err)
				}
			}
		}
	}
	// At this point we can create a request since we have all intermediate keys to authenticate
	// the payload.
	return e.Bootstrapper.SendDRKeyReq(ctx, &trip, valTime)
}

type BestEffortProvider struct {
	Fetcher grpc.DRKeyFetcher
}

func (p *BestEffortProvider) GetKey(ctx context.Context, meta drkey.Lvl2Meta,
	valTime time.Time) (*drkey.Lvl2Key, error) {
	return p.Fetcher.GetDRKeyLvl2(ctx, meta, valTime)
}

type FakeProvider struct{}

func (p *FakeProvider) GetKey(ctx context.Context, meta drkey.Lvl2Meta,
	_ time.Time) (*drkey.Lvl2Key, error) {
	return &drkey.Lvl2Key{
		Lvl2Meta: drkey.Lvl2Meta{
			KeyType:  drkey.AS2Host,
			Protocol: "colibri",
			Epoch:    drkey.NewEpoch(0, 100),
			SrcIA:    meta.SrcIA,
			DstIA:    meta.DstIA,
			DstHost:  meta.DstHost,
		},
		Key: drkey.DRKey([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	}, nil
}
