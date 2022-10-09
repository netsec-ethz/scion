package colibri

import (
	"encoding/hex"
	"net"
	"testing"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	ct "github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/stretchr/testify/require"
)

// TestSerializeBaseRequest checks that the two possible serializations of a EER base requests
// are identical. One happens at the end-host level in the source AS, and the other at any other AS.
func TestSerializeBaseRequest(t *testing.T) {
	cases := map[string]struct {
		req   *BaseRequest
		steps base.PathSteps
	}{
		"two_steps": {
			req: &BaseRequest{
				Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
				Index:     3,
				TimeStamp: util.SecsToTime(1),
				SrcHost:   net.ParseIP("10.1.1.1"),
				DstHost:   net.ParseIP("10.2.2.2"),
			},
			steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:112", 0),
		},
		"three_steps": {
			req: &BaseRequest{
				Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
				Index:     3,
				TimeStamp: util.SecsToTime(1),
				SrcHost:   net.ParseIP("10.1.1.1"),
				DstHost:   net.ParseIP("10.2.2.2"),
			},
			steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
				1, "1-ff00:0:112", 0),
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e2eReq := e2e.Request{
				Request: *base.NewRequest(
					tc.req.TimeStamp,
					&tc.req.Id,
					tc.req.Index,
					len(tc.steps)),
				SrcHost: tc.req.SrcHost,
				DstHost: tc.req.DstHost,
			}
			require.Equal(t, minSizeBaseReq(tc.req), e2eReq.Len())

			buff := make([]byte, minSizeBaseReq(tc.req))
			serializeBaseRequest(buff, tc.req)

			// now serialize using the transit AS code:
			transitBuff := make([]byte, e2eReq.Len())
			e2eReq.Serialize(transitBuff, base.SerializeImmutable)
			require.Equalf(t, buff, transitBuff, "representations differ: expected: %s\nactual:%s",
				hex.EncodeToString(buff), hex.EncodeToString(transitBuff))
		})
	}
}

func TestSerializeE2EReservationSetup(t *testing.T) {
	cases := map[string]struct {
		req *E2EReservationSetup
	}{
		"two_steps_no_segments": {
			req: &E2EReservationSetup{
				BaseRequest: BaseRequest{
					Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
					Index:     3,
					TimeStamp: util.SecsToTime(1),
					SrcHost:   net.ParseIP("10.1.1.1"),
					DstHost:   net.ParseIP("10.2.2.2"),
				},
				Steps:       ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:112", 0),
				RequestedBW: 0xdd,
			},
		},
		"three_steps_two_segments": {
			req: &E2EReservationSetup{
				BaseRequest: BaseRequest{
					Id:        *ct.MustParseID("ff00:0:111", "0123456789abcdef01234567"),
					Index:     3,
					TimeStamp: util.SecsToTime(1),
					SrcHost:   net.ParseIP("10.1.1.1"),
					DstHost:   net.ParseIP("10.2.2.2"),
				},
				Steps: ct.NewSteps(0, "1-ff00:0:111", 1, 1, "1-ff00:0:110", 2,
					1, "1-ff00:0:112", 0),
				RequestedBW: 0xdd,
				Segments: []reservation.ID{
					*ct.MustParseID("ff00:0:111", "01234567"),
					*ct.MustParseID("ff00:0:112", "89abcdef"),
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e2eReq := e2e.SetupReq{
				Request: e2e.Request{
					Request: *base.NewRequest(
						tc.req.TimeStamp,
						&tc.req.Id,
						tc.req.Index,
						len(tc.req.Steps)),
					SrcHost: tc.req.SrcHost,
					DstHost: tc.req.DstHost,
				},
				Steps:                  tc.req.Steps,
				CurrentStep:            1,
				RequestedBW:            tc.req.RequestedBW,
				SegmentRsvs:            tc.req.Segments,
				CurrentSegmentRsvIndex: 0,
			}
			require.Equal(t, minSizeE2ESetupReq(tc.req), e2eReq.Len())
			buff := make([]byte, minSizeE2ESetupReq(tc.req))
			serializeE2EReservationSetup(buff, tc.req)

			// now serialize using the transit AS code:
			transitBuff := make([]byte, e2eReq.Len())
			e2eReq.Serialize(transitBuff, base.SerializeImmutable)
			require.Equalf(t, buff, transitBuff, "representations differ\n"+
				"expected: %s\n"+
				"actual:   %s", hex.EncodeToString(buff), hex.EncodeToString(transitBuff))
		})
	}
}
