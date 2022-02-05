package bootstrap

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/drkey"
)

type DRKeyProvider interface {
	GetKey(ctx context.Context, meta drkey.Lvl2Meta, valTime time.Time) (*drkey.Lvl2Key, error)
}
