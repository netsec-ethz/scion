package bootstrap

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
)

func NewTestBootstrapProvider(localIA addr.IA, builder SetReqBuilder, mgr ExtendedReservationManager,
	db drkey.Lvl2DB, cryptoProvider ClientCryptoProvider) *BootstrapProvider {
	return &BootstrapProvider{
		LocalIA:        localIA,
		Builder:        builder,
		Mgr:            mgr,
		Lvl2DB:         db,
		CryptoProvider: cryptoProvider,
	}
}
