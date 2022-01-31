package bootstrap

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/drkey"
)

type DRKeyProvider interface {
	GetLvl1(ctx context.Context, meta drkey.Lvl1Meta, valTime time.Time) (*drkey.Lvl1Key, error)
}
