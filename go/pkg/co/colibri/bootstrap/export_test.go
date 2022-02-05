package bootstrap

import (
	"github.com/scionproto/scion/go/lib/addr"
)

func NewTestBootstrapProvider(localIA addr.IA, builder SetReqBuilder, mgr ExtendedReservationManager,
	drkeyProvider DRKeyProvider, cryptoProvider AsymClientProvider) *BootstrapProvider {
	return &BootstrapProvider{
		localIA:        localIA,
		builder:        builder,
		Mgr:            mgr,
		DRKeyProvider:  drkeyProvider,
		CryptoProvider: cryptoProvider,
	}
}
