package bootstrap

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/pkg/co/colibri/bootstrap/grpc"
)

type DRKeyProvider interface {
	GetKey(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (*drkey.Lvl2Key, error)
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
