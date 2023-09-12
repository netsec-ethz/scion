package hummingbird_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

func TestFlyoverHopSerializeDecodeFlyover(t *testing.T) {
	want := &hummingbird.FlyoverHopField{
		HopField: path.HopField{
			IngressRouterAlert: true,
			EgressRouterAlert:  true,
			ExpTime:            63,
			ConsIngress:        1,
			ConsEgress:         0,
			Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        782,
		Bw:           23,
		ResStartTime: 233,
		Duration:     11,
	}
	b := make([]byte, hummingbird.FlyoverLen)
	assert.NoError(t, want.SerializeTo(b))

	got := &hummingbird.FlyoverHopField{}
	assert.NoError(t, got.DecodeFromBytes(b))
	assert.Equal(t, want, got)
}

func TestFlyoverHopSerializeDecode(t *testing.T) {
	want := &hummingbird.FlyoverHopField{
		HopField: path.HopField{
			IngressRouterAlert: true,
			EgressRouterAlert:  false,
			ExpTime:            63,
			ConsIngress:        1,
			ConsEgress:         0,
			Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      false,
		ResID:        0,
		Bw:           0,
		ResStartTime: 0,
		Duration:     0,
	}
	b := make([]byte, hummingbird.FlyoverLen)
	assert.NoError(t, want.SerializeTo(b))

	got := &hummingbird.FlyoverHopField{}
	assert.NoError(t, got.DecodeFromBytes(b))
	assert.Equal(t, want, got)
}
