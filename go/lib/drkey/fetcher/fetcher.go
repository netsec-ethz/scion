package fetcher

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	drkeyctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type Fetcher struct {
	Dialer libgrpc.Dialer
}

func (f *Fetcher) Lvl1(ctx context.Context, meta drkey.Lvl1Meta) (drkey.Lvl1Key, error) {
	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := drkeyctrl.IntraLvl1ToProtoRequest(meta)
	if err != nil {
		return drkey.Lvl1Key{},
			serrors.WrapStr("parsing AS-AS request to protobuf", err)
	}
	rep, err := client.IntraLvl1(ctx, protoReq)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("requesting AS-AS key", err)
	}
	key, err := drkeyctrl.GetASASKeyFromReply(meta, rep)
	if err != nil {
		return drkey.Lvl1Key{}, serrors.WrapStr("obtaining AS-AS key from reply", err)
	}
	return key, nil
}

func (f *Fetcher) ASHost(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := drkeyctrl.ASHostMetaToProtoRequest(meta)
	if err != nil {
		return drkey.ASHostKey{},
			serrors.WrapStr("parsing AS-Host request to protobuf", err)
	}
	rep, err := client.ASHost(ctx, protoReq)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("requesting AS-Host key", err)
	}
	key, err := drkeyctrl.GetASHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("obtaining AS-Host key from reply", err)
	}
	return key, nil
}

func (f *Fetcher) HostAS(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {
	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := drkeyctrl.HostASMetaToProtoRequest(meta)
	if err != nil {
		return drkey.HostASKey{},
			serrors.WrapStr("parsing Host-AS request to protobuf", err)
	}
	rep, err := client.HostAS(ctx, protoReq)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("requesting Host-AS key", err)
	}
	key, err := drkeyctrl.GetHostASKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("obtaining Host-AS key from reply", err)
	}
	return key, nil
}

func (f *Fetcher) HostHost(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := drkeyctrl.HostHostMetaToProtoRequest(meta)
	if err != nil {
		return drkey.HostHostKey{},
			serrors.WrapStr("parsing Host-Host request to protobuf", err)
	}
	rep, err := client.HostHost(ctx, protoReq)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("requesting Host-Host key", err)
	}
	key, err := drkeyctrl.GetHostHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("obtaining Host-Host key from reply", err)
	}
	return key, nil
}
