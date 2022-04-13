// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	ctrl "github.com/scionproto/scion/go/lib/ctrl/drkey"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/serrors"
	sd_drkey "github.com/scionproto/scion/go/pkg/daemon/drkey"
	sc_grpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// DRKeyFetcher obtains end-host key from the local CS.
type Fetcher struct {
	Dialer sc_grpc.Dialer
}

var _ sd_drkey.Fetcher = (*Fetcher)(nil)

func (f Fetcher) ASHostKey(ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {

	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := ctrl.ASHostMetaToProtoRequest(meta)
	if err != nil {
		return drkey.ASHostKey{},
			serrors.WrapStr("parsing AS-HOST request to protobuf", err)
	}
	rep, err := client.ASHost(ctx, protoReq)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("requesting AS-HOST key", err)
	}

	key, err := ctrl.GetASHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.WrapStr("obtaining AS-HOST key from reply", err)
	}

	return key, nil
}

func (f Fetcher) HostASKey(ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {

	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := ctrl.HostASMetaToProtoRequest(meta)
	if err != nil {
		return drkey.HostASKey{},
			serrors.WrapStr("parsing HOST-AS request to protobuf", err)
	}
	rep, err := client.HostAS(ctx, protoReq)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("requesting HOST-AS key", err)
	}

	key, err := ctrl.GetHostASKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.WrapStr("obtaining HOST-AS key from reply", err)
	}

	return key, nil
}

func (f Fetcher) HostHostKey(ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	conn, err := f.Dialer.Dial(ctx, addr.SvcCS)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq, err := ctrl.HostHostMetaToProtoRequest(meta)
	if err != nil {
		return drkey.HostHostKey{},
			serrors.WrapStr("parsing HOST-AS request to protobuf", err)
	}
	rep, err := client.HostHost(ctx, protoReq)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("requesting Host-Host key", err)
	}

	key, err := ctrl.GetHostHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("obtaining Host-Host key from reply", err)
	}

	return key, nil
}
