package path

import (
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/snet"
)

type Hummingbird struct {
	// Raw is the raw representation of this path. This data should not be
	// modified because it is potentially shared.
	Raw []byte
}

var _ snet.DataplanePath = (*Hummingbird)(nil)

func NewHbirdFromDecoded(d *hummingbird.Decoded) (Hummingbird, error) {
	buf := make([]byte, d.Len())
	if err := d.SerializeTo(buf); err != nil {
		return Hummingbird{}, serrors.WrapStr("serializing decoded Hummingbird path", err)
	}
	return Hummingbird{Raw: buf}, nil
}

func (p Hummingbird) SetPath(s *slayers.SCION) error {
	var sp hummingbird.Raw
	if err := sp.DecodeFromBytes(p.Raw); err != nil {
		return err
	}
	s.Path, s.PathType = &sp, sp.Type()
	return nil
}

func (p Hummingbird) SetExtensions(*slayers.SCION, *snet.PacketInfo) error {
	return nil
}
