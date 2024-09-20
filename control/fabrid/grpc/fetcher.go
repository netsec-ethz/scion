// Copyright 2024 ETH Zurich
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
	"errors"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	defaultRPCDialTimeout time.Duration = 2 * time.Second
)

var errNotReachable = serrors.New("remote not reachable")
var errNotFound = serrors.New("FABRID local policy is not found")

type FabridControlPlaneFetcher interface {
	GetRemotePolicy(ctx context.Context, remoteIA addr.IA,
		remotePolicyIdentifier uint32) (*experimental.RemotePolicyDescriptionResponse, error)
	GetRemoteMaps(ctx context.Context, remoteIA addr.IA) (*experimental.DetachedMapsResponse, error)
}

type BasicFabridControlPlaneFetcher struct {
	Dialer     libgrpc.Dialer
	Router     snet.Router
	MaxRetries int

	errorPaths map[snet.PathFingerprint]struct{}
}

func (f *BasicFabridControlPlaneFetcher) GetRemoteMaps(
	ctx context.Context,
	remoteIA addr.IA,
) (*experimental.DetachedMapsResponse, error) {
	var errList serrors.List
	f.errorPaths = make(map[snet.PathFingerprint]struct{})
	for i := 0; i < f.MaxRetries; i++ {
		rep, err := f.attemptFetchRemote(ctx, remoteIA, func(ctx context.Context,
			client experimental.FABRIDInterServiceClient) (interface{}, error) {
			return client.DetachedMaps(ctx, &experimental.DetachedMapsRequest{})
		})
		if errors.Is(err, errNotReachable) || (err != nil && strings.Contains(err.Error(),
			errNotFound.Error())) {
			return &experimental.DetachedMapsResponse{}, serrors.New(
				"remote maps fetch fetch failed", "try", i+1, "peer", remoteIA,
				"err", err)
		} else if err != nil {
			errList = append(errList,
				serrors.WrapStr("fetching policy", err, "try", i+1, "peer", remoteIA),
			)
			continue
		}
		maps, ok := rep.(*experimental.DetachedMapsResponse)
		if !ok {
			return &experimental.DetachedMapsResponse{}, serrors.New(
				"remote policy fetch fetch failed, invalid response", "try", i+1,
				"peer", remoteIA)
		}
		return maps, nil
	}
	return &experimental.DetachedMapsResponse{}, serrors.WrapStr(
		"reached max retry attempts fetching remote policy",
		errList,
	)
}

func (f *BasicFabridControlPlaneFetcher) GetRemotePolicy(
	ctx context.Context,
	remoteIA addr.IA,
	remotePolicyIdentifier uint32,
) (*experimental.RemotePolicyDescriptionResponse, error) {
	var errList serrors.List
	f.errorPaths = make(map[snet.PathFingerprint]struct{})
	for i := 0; i < f.MaxRetries; i++ {
		rep, err := f.attemptFetchRemote(ctx, remoteIA, func(ctx context.Context,
			client experimental.FABRIDInterServiceClient) (interface{}, error) {
			return client.LocalPolicyDescription(ctx,
				&experimental.LocalPolicyDescriptionRequest{
					PolicyIdentifier: remotePolicyIdentifier})
		})
		if errors.Is(err, errNotReachable) || (err != nil && strings.Contains(err.Error(),
			errNotFound.Error())) {
			return &experimental.RemotePolicyDescriptionResponse{}, serrors.New(
				"remote policy fetch fetch failed", "try", i+1, "peer", remoteIA,
				"err", err)
		} else if err != nil {
			errList = append(errList,
				serrors.WrapStr("fetching policy", err, "try", i+1, "peer", remoteIA),
			)
			continue
		}
		policyDescr, ok := rep.(*experimental.LocalPolicyDescriptionResponse)
		if !ok {
			return &experimental.RemotePolicyDescriptionResponse{}, serrors.New(
				"remote policy fetch fetch failed, invalid response", "try", i+1,
				"peer", remoteIA)
		}
		return &experimental.RemotePolicyDescriptionResponse{Description: policyDescr.
			Description}, nil
	}
	return &experimental.RemotePolicyDescriptionResponse{}, serrors.WrapStr(
		"reached max retry attempts fetching remote policy",
		errList,
	)
}

func (f *BasicFabridControlPlaneFetcher) attemptFetchRemote(
	ctx context.Context,
	srcIA addr.IA,
	fetchingFunc func(ctx context.Context, client experimental.FABRIDInterServiceClient) (
		interface{}, error),
) (interface{}, error) {

	path, err := f.pathToDst(ctx, srcIA)
	if err != nil {
		return nil, err
	}
	remote := &snet.SVCAddr{
		IA:      srcIA,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	dialCtx, cancelF := context.WithTimeout(ctx, defaultRPCDialTimeout)
	defer cancelF()
	conn, err := f.Dialer.Dial(dialCtx, remote)
	if err != nil {
		return nil, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := experimental.NewFABRIDInterServiceClient(conn)
	rep, err := fetchingFunc(ctx, client)
	if err != nil {
		return nil, serrors.WrapStr("requesting ", err)
	}
	return rep, nil
}

func (f *BasicFabridControlPlaneFetcher) pathToDst(ctx context.Context, dst addr.IA) (snet.Path,
	error) {
	paths, err := f.Router.AllRoutes(ctx, dst)
	if err != nil {
		return nil, serrors.Wrap(errNotReachable, err)
	}
	if len(paths) == 0 {
		return nil, errNotReachable
	}
	for _, p := range paths {
		if _, ok := f.errorPaths[snet.Fingerprint(p)]; ok {
			continue
		}
		f.errorPaths[snet.Fingerprint(p)] = struct{}{}
		return p, nil
	}
	// we've tried out all the paths; we reset the map to retry them.
	f.errorPaths = make(map[snet.PathFingerprint]struct{})
	return paths[0], nil
}
