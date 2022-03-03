package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstorage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
)

// SetReqBuilder builds a request that will be protected over stitched COLIBRI
// segments. This allows to protect the SegR setup so that it cannot
// be disrupted by best-effort traffic.
type SetReqBuilder interface {
	BuildSetReq(ctx context.Context, trip colibri.FullTrip, dst addr.IA) (*segment.SetupReq, error)
}

type builder struct {
	localIA addr.IA
	topo    topology.Topology

	Store reservationstorage.Store
}

// BuildSetReq creates a COLIBRI EER and returns a SetupRequest whose path (the path over
//	which the SetupRequest will be sent) corresponds to such a reservation.
func (b *builder) BuildSetReq(ctx context.Context,
	trip colibri.FullTrip, dst addr.IA) (*segment.SetupReq, error) {
	_, path, err := b.createEER(ctx, trip.Segments(), dst, 5)

	if err != nil {
		return nil, serrors.WrapStr("creating EER to send SetupRequest", err)
	}

	suffix := make([]byte, 12)
	rand.Read(suffix)

	transparentPath, err := reservation.TransparentPathFromSnet(path)
	if err != nil {
		return nil, serrors.WrapStr("building transparent path", err)
	}
	pathType := lib_res.UpPath
	if b.topo.Core() {
		pathType = lib_res.CorePath
	}

	return &segment.SetupReq{
		Request: reservation.Request{
			MsgId: reservation.MsgId{
				ID: lib_res.ID{
					ASID:   b.localIA.A,
					Suffix: suffix,
				},
				Index:     0,
				Timestamp: time.Now(),
			},
			Path: transparentPath,
		},
		ExpirationTime: time.Now().Add(3 * time.Minute),
		// RLC:            e.RLC,
		PathType:     pathType,
		MinBW:        5,
		MaxBW:        15,
		SplitCls:     7,
		PathProps:    lib_res.NewPathEndProps(true, true, true, true),
		AllocTrail:   lib_res.AllocationBeads{}, // at source
		PathAtSource: transparentPath,
	}, nil
}

func (b *builder) createEER(ctx context.Context, segments []lib_res.ID, dst addr.IA,
	requestBW lib_res.BWCls) (lib_res.ID, snet.Path, error) {
	suffix := make([]byte, 12)
	rand.Read(suffix)
	setupRequest := &e2e.SetupReq{
		Request: reservation.Request{
			MsgId: reservation.MsgId{
				ID: lib_res.ID{
					ASID:   b.localIA.A,
					Suffix: suffix,
				},
				Index:     0,
				Timestamp: time.Now(),
			},
		},
		SrcIA:   b.localIA,
		DstIA:   dst,
		DstHost: net.IPv4(127, 0, 0, 1), // dst.Host.IP
		// at the moment we use lo address to indicate it
		// is a reservation to the same COLIBRI service.
		SegmentRsvs:            segments,
		CurrentSegmentRsvIndex: 0,
		RequestedBW:            requestBW,
		AllocationTrail:        nil,
	}
	resp, err := b.Store.AdmitE2EReservation(ctx, setupRequest)
	if err != nil {
		return setupRequest.ID, nil, err
	}
	path, err := b.pathFromE2EResp(setupRequest.ID, resp)

	return setupRequest.ID, path, err
}

func (b *builder) pathFromE2EResp(resID lib_res.ID, resp e2e.SetupResponse) (snet.Path, error) {
	e2eResp, ok := resp.(*e2e.SetupResponseSuccess)
	if !ok {
		return nil, fmt.Errorf("error")
	}
	token, err := lib_res.TokenFromRaw(e2eResp.Token)
	if err != nil {
		return nil, serrors.WrapStr("decoding token in colibri service", err)
	}
	colPath := e2e.DeriveColibriPath(&resID, token)
	rawPath := make([]byte, colPath.Len())
	err = colPath.SerializeTo(rawPath)
	if err != nil {
		return nil, serrors.WrapStr("serializing a colibri path in colibri service", err)
	}
	egressId := ""
	if len(colPath.HopFields) > 0 {
		egressId = fmt.Sprintf("%d", colPath.HopFields[0].EgressId)
	}
	egress, err := strconv.Atoi(egressId)
	if err != nil {
		return nil, serrors.WrapStr("obtaining next hop from egress", err,
			"egress", egressId)
	}
	addr, ok := b.topo.UnderlayNextHop(common.IFIDType(egress))
	if !ok {
		return nil, serrors.New("obtaining next hop from egress id, egress not present",
			"egress", egress)
	}
	return &path.Path{
		SPath: spath.Path{
			Raw:  rawPath,
			Type: colPath.Type(),
		},
		NextHop: addr,
	}, nil
}

// FakeBuilder do not create the EER when creating the SegR setup.
type FakeBuilder struct{}

func (f FakeBuilder) BuildSetReq(_ context.Context,
	trip colibri.FullTrip, dst addr.IA) (*segment.SetupReq, error) {
	transparentPath := reservation.TransparentPath{
		Steps: []reservation.PathStep{
			{
				IA: trip.SrcIA(),
			},
			// omit paths in the middle
			{
				IA: trip.DstIA(),
			},
		},
	}
	return &segment.SetupReq{
		Request: reservation.Request{
			Path: &transparentPath,
		},
	}, nil
}
