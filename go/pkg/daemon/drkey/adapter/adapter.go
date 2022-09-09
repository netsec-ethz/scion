package adapter

import (
	"context"

	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/drkey"
)

type drkeyGetterWithDaemon struct {
	daemon daemon.Connector
}

func (g *drkeyGetterWithDaemon) ASHostKey(ctx context.Context, meta drkey.ASHostMeta) (
	drkey.ASHostKey, error) {

	return g.daemon.DRKeyGetASHostKey(ctx, meta)
}

func WithDaemon(daemon daemon.Connector) *drkeyGetterWithDaemon {
	return &drkeyGetterWithDaemon{
		daemon: daemon,
	}
}
