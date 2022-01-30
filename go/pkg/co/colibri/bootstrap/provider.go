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
	"github.com/scionproto/scion/go/co/reservationstore"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri"
	lib_res "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
)

type ColibriProvider interface {
	BootstrapLvl1Key(ctx context.Context, trip colibri.FullTrip) (*drkey.Lvl1Key, error)

	// SetupUpSegR establishes a SegR from A to C using segments = {upSegR + NR}.
	// The SegRSetup request travels through a EER established
	// over the same segments.
	//
	// Precondition:
	// - upSegR = {A -> B1 -> Bi -> Bn}
	// - NR = {Bn->C}
	// - We have DRKeys for every on-path AS (included C)
	//
	// Postcondition:
	// - if no error, a SegR from A to C has been allocated.
	SetupUpSegR(ctx context.Context, trip colibri.FullTrip, dst addr.IA) (*colibri.ReservationLooks, error)
	TearDownSeg(ctx context.Context, seg *colibri.ReservationLooks) error
	LookupNR(ctx context.Context, transferIA addr.IA, dst addr.IA) (*colibri.ReservationLooks, error)

	// GetLvl1 returns a lvl1 key from persitance. If it is not in persistance
	// it tries to fetch it from the remote CS via best-effort
	GetLvl1(context.Context, drkey.Lvl1Meta, uint32) (*drkey.Lvl1Key, error)
	StoreLvl1(context.Context, *drkey.Lvl1Key) error
}

type Provider struct {
	localIA      addr.IA
	TopoProvider topology.Provider
	Mgr          reservationstore.Manager
}

func (p *Provider) BootstrapLvl1Key(ctx context.Context, trip colibri.FullTrip) (drkey.Lvl1Key, error) {
	panic("not implemented")
	// prepare pb.Lvl1Req
	// lvl1:= Lvl1Req{
	// 	certificate x509.certificate
	// 	valTime uint32
	//  Path      *TransparentPath
	// }

	// return Mgr.Lvl1(ctx, lvl1req)
}

func (p *Provider) SetupUpSegR(ctx context.Context, trip colibri.FullTrip, dst addr.IA) (lib_res.ID, error) {

	// Create EER to dst. We let the EER expire without explicitely tearing it down.
	_, path, err := p.createEER(ctx, trip.Segments(), dst, 5)

	if err != nil {
		return lib_res.ID{}, serrors.WrapStr("creating EER to send SetupRequest", err)
	}

	suffix := make([]byte, 12)
	rand.Read(suffix)

	transparentPath, err := reservation.TransparentPathFromSnet(path)
	if err != nil {
		return lib_res.ID{}, serrors.WrapStr("building transparent path", err)
	}
	pathType := lib_res.UpPath
	if p.TopoProvider.Get().Core() {
		pathType = lib_res.CorePath
	}

	segSetupReq := segment.SetupReq{
		Request: reservation.Request{
			MsgId: reservation.MsgId{
				ID: lib_res.ID{
					ASID:   p.localIA.A,
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
	}

	// This initSegmentReservation travels over COLIBRI
	if err := p.Mgr.SetupRequest(ctx, &segSetupReq); err != nil {
		return lib_res.ID{}, serrors.WrapStr("init segment reservation over EER", err)
	}

	// At this point we have establish a segR from local AS to dst
	segReservations, err := p.Mgr.Store().ListReservations(ctx, dst, pathType)
	if err != nil {
		return lib_res.ID{}, serrors.WrapStr("listing reservations to dst", err)
	}
	if len(segReservations) == 0 {
		return lib_res.ID{}, serrors.New("No reservations after bootstrap segR", "dst", dst)
	}

	return segReservations[0].Id, nil
}

func (p *Provider) TearDownSeg(ctx context.Context, segR colibri.ReservationLooks) error {

	panic("Not implemented")
}

func (p *Provider) ListStitchableSegments(ctx context.Context, dst addr.IA) (*colibri.StitchableSegments, error) {
	return p.Mgr.Store().ListStitchableSegments(ctx, dst)
}
func (p *Provider) LookupNR(ctx context.Context, transferIA addr.IA, dst addr.IA) (lib_res.ID, error) {
	panic("Not implemented")
}

func (p *Provider) createEER(ctx context.Context, segments []lib_res.ID, dst addr.IA,
	requestBW lib_res.BWCls) (lib_res.ID, snet.Path, error) {
	suffix := make([]byte, 12)
	rand.Read(suffix)
	setupRequest := &e2e.SetupReq{
		Request: reservation.Request{
			MsgId: reservation.MsgId{
				ID: lib_res.ID{
					ASID:   p.localIA.A,
					Suffix: suffix,
				},
				Index:     0,
				Timestamp: time.Now(),
			},
		},
		SrcIA:   p.localIA,
		DstIA:   dst,
		DstHost: net.IPv4(127, 0, 0, 1), // dst.Host.IP
		// at the moment we use lo address to indicate it is a reservation to the same COLIBRI service
		SegmentRsvs:            segments,
		CurrentSegmentRsvIndex: 0,
		RequestedBW:            requestBW,
		AllocationTrail:        nil,
	}
	resp, err := p.Mgr.Store().AdmitE2EReservation(ctx, setupRequest)
	if err != nil {
		return setupRequest.ID, nil, err
	}
	path, err := p.pathFromE2EResp(setupRequest.ID, resp)

	return setupRequest.ID, path, err
}

func (p *Provider) pathFromE2EResp(resID lib_res.ID, resp e2e.SetupResponse) (snet.Path, error) {
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
	addr, ok := p.TopoProvider.Get().UnderlayNextHop(common.IFIDType(egress))
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

func (p *Provider) cleanRsv(ctx context.Context, id *lib_res.ID,
	idx lib_res.IndexNumber) error {

	// log.Debug("cleaning e2e rsv", "id", id)
	panic("not implemented")
}
