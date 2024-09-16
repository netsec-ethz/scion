// Copyright 2024 ETH Zürich
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

package control

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	drpb "github.com/scionproto/scion/pkg/proto/drkey"
)

type SecretValue struct {
	EpochBegin time.Time
	EpochEnd   time.Time
	Key        [16]byte
}

type PolicyIPRange struct {
	MPLSLabel uint32
	IPPrefix  *net.IPNet
}

type Fetcher struct {
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr
	dp         Dataplane
}

// NewFetcher returns a new fetcher that is used to make queries to the control service.
func NewFetcher(localIP string, csAddr string, dp Dataplane) (*Fetcher, error) {
	localAddr := &net.TCPAddr{
		IP:   net.ParseIP(localIP),
		Port: 0,
	}
	remoteTcpAddr, err := net.ResolveTCPAddr("tcp", csAddr)
	if err != nil {
		return nil, err
	}
	f := &Fetcher{
		localAddr:  localAddr,
		remoteAddr: remoteTcpAddr,
		dp:         dp,
	}
	return f, nil
}

// StartFabridPolicyFetcher starts the FABRID policy fetcher that fetches the FABRID
// policies from the local control service every 30 minutes.
func (f *Fetcher) StartFabridPolicyFetcher() {
	retryAfterErrorDuration := 10 * time.Second
	for {
		mplsPolicyResp, err := f.queryFabridPolicies()

		if err != nil {
			log.Debug("Error while querying the FABRID policies from local control service",
				"err", err)
			time.Sleep(retryAfterErrorDuration)
			continue
		}
		if !mplsPolicyResp.Update {
			time.Sleep(30 * time.Minute)
			continue
		}

		log.Debug("Updated FABRID policies")
		err = f.dp.UpdateFabridPolicies(ipPoliciesMapFromPB(mplsPolicyResp.MplsIpMap),
			mplsPolicyResp.MplsInterfacePoliciesMap)
		if err != nil {
			log.Debug("Error while adding FABRID policies", "err", err)
			time.Sleep(retryAfterErrorDuration)
			continue
		}

		time.Sleep(30 * time.Minute)
	}
}

func ipPoliciesMapFromPB(mplsPolicyResp map[uint32]*experimental.
	MPLSIPArray) map[uint32][]*PolicyIPRange {
	res := make(map[uint32][]*PolicyIPRange)
	for key, ipArray := range mplsPolicyResp {

		for _, ipRange := range ipArray.Entry {
			var m net.IPMask
			if len(ipRange.Ip) == 4 {
				m = net.CIDRMask(int(ipRange.Prefix), 8*net.IPv4len)
			} else {
				m = net.CIDRMask(int(ipRange.Prefix), 8*net.IPv6len)
			}
			res[key] = append(res[key], &PolicyIPRange{
				IPPrefix:  &net.IPNet{IP: ipRange.Ip, Mask: m},
				MPLSLabel: ipRange.MplsLabel,
			})
		}
	}
	return res
}

func (f *Fetcher) queryFabridPolicies() (*experimental.MPLSMapResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.DialTCP("tcp", f.localAddr, f.remoteAddr)
	}
	grpcconn, err := grpc.DialContext(ctx, f.remoteAddr.String(),
		grpc.WithInsecure(), grpc.WithContextDialer(dialer))
	if err != nil {
		return nil, err
	}
	defer grpcconn.Close()
	client := experimental.NewFABRIDIntraServiceClient(grpcconn)
	rep, err := client.MPLSMap(ctx,
		&experimental.MPLSMapRequest{
			Hash: nil,
		})
	if err != nil {
		return nil, serrors.WrapStr("requesting policy", err)
	}
	return rep, err
}

// StartSecretUpdater is responsible for querying the local control service to request the
// DRKey secret values for the registered DRKey protocols. (e.g. FABRID, SCMP, ...)
// It will automatically register the received DRKey secrets in the dataplane and start
// prefetching the upcoming secret values 3 minutes before they become valid.
func (f *Fetcher) StartSecretUpdater(protocols []string) {
	retryAfterErrorDuration := 5 * time.Second
	prefetchTime := time.Minute * 3
	runProtocol := func(protocolID drkey.Protocol) {
		// First we make sure that we have a secret that is valid now.
		// After that we start prefetching. In case we initially receive a secret value
		// that expires before the prefetch time, we prefetch the new secret value immediately.
		isPrefetching := false
		for {
			t := time.Now()
			if isPrefetching {
				t = t.Add(prefetchTime)
			}
			sv, err := f.queryASSecret(protocolID, t)
			if err != nil {
				log.Debug("Error while querying secret value from local control service",
					"protocol", protocolID, "err", err)
				time.Sleep(retryAfterErrorDuration)
				continue
			}
			err = f.dp.AddDRKeySecret(int32(protocolID), sv)
			if err != nil {
				log.Debug("Error while adding drkey", "protocol", protocolID, "err", err)
				time.Sleep(retryAfterErrorDuration)
				continue
			}
			sleepTime := max(time.Until(sv.EpochEnd)-prefetchTime, 0)
			time.Sleep(sleepTime)
			isPrefetching = true
		}
	}
	for _, p := range protocols {
		pID, ok := drkey.ProtocolStringToId("PROTOCOL_" + p)
		if ok {
			log.Debug("Register DRKey secret fetcher for", "protocol", p)
			go func(protocol drkey.Protocol) {
				defer log.HandlePanic()
				runProtocol(protocol)
			}(pID)
		}
	}
}

func (f *Fetcher) queryASSecret(
	protocolID drkey.Protocol, minValStart time.Time) (SecretValue, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.DialTCP("tcp", f.localAddr, f.remoteAddr)
	}
	grpcconn, err := grpc.DialContext(ctx, f.remoteAddr.String(),
		grpc.WithInsecure(), grpc.WithContextDialer(dialer))
	if err != nil {
		return SecretValue{}, err
	}
	defer grpcconn.Close()
	client := cppb.NewDRKeyIntraServiceClient(grpcconn)
	req := &cppb.DRKeySecretValueRequest{
		ProtocolId: drpb.Protocol(protocolID),
		ValTime:    timestamppb.New(minValStart),
	}
	res, err := client.DRKeySecretValue(ctx, req)
	if err != nil {
		return SecretValue{}, err
	}
	newKey := [16]byte{}
	copy(newKey[:16], res.Key[:16])
	sv := SecretValue{
		EpochBegin: res.EpochBegin.AsTime(),
		EpochEnd:   res.EpochEnd.AsTime(),
		Key:        newKey,
	}
	return sv, nil
}
