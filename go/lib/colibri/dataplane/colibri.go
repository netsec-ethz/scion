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

// Package colibri contains methods for the creation and verification of the colibri packet
// timestamp and validation fields.
package colibri

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// packetLifetime denotes the maximal lifetime of a packet
	packetLifetime = 2 * time.Second
	// clockSkew denotes the maximal clock skew
	clockSkew = time.Second
	// TimestampResolution denotes the resolution of the epic timestamp
	TimestampResolution = 4 * time.Nanosecond
	// TickDuration denotes the length of one Colibri tick in seconds
	TickDuration = reservation.SecsPerTick
	// ExpirationOffset denotes the offset that is subtracted from the expiration time to
	// get the reference time for the high-precision timestamp.
	ExpirationOffset = reservation.TicksInE2ERsv * reservation.SecsPerTick * time.Second
	// LengthInputData denotes the length of InputData in bytes
	LengthInputData = 30
	// LengthInputDataRound16 denotes the LengthInputData rounded to the next multiple of 16
	LengthInputDataRound16 = ((LengthInputData-1)/16 + 1) * 16
)

var zeroInitVector [aes.BlockSize]byte

// CreateColibriTimestamp creates the COLIBRI Timestamp from tsRel, coreID, and coreCounter.
func CreateColibriTimestamp(tsRel uint32, coreID uint8, coreCounter uint32) colibri.Timestamp {
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             TsRel                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |    CoreID     |                  CoreCounter                  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	pktId := (uint32(coreID) << 24) | uint32(coreCounter)
	return CreateColibriTimestampCustom(tsRel, pktId)
}

// CreateColibriTimestampCustom creates the COLIBRI Timestamp from tsRel and pckId.
func CreateColibriTimestampCustom(tsRel uint32, pktId uint32) colibri.Timestamp {
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             TsRel                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             PckId                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	ts := colibri.Timestamp{}
	binary.BigEndian.PutUint32(ts[:4], tsRel)
	binary.BigEndian.PutUint32(ts[4:], pktId)
	return ts
}

// ParseColibriTimestamp reads tsRel, coreID, and coreCounter from the Timestamp.
func ParseColibriTimestamp(ts colibri.Timestamp) (tsRel uint32, coreID uint8, coreCounter uint32) {
	var pktId uint32
	tsRel, pktId = ParseColibriTimestampCustom(ts)
	coreID = uint8(pktId >> 24)
	coreCounter = pktId & 0x00ffffff
	return
}

// ParseColibriTimestampCustom reads tsRel and pckId from the Timestamp.
func ParseColibriTimestampCustom(ts colibri.Timestamp) (tsRel uint32, pktId uint32) {
	bothParts := binary.BigEndian.Uint64(ts[:])
	tsRel = uint32(bothParts >> 32)
	pktId = uint32(bothParts & 0x00000000ffffffff)
	return
}

// CreateTsRel returns tsRel, which encodes the current time (the time when this function is called)
// relative to the expiration time minus 16 seconds. The input expiration tick must be specified in
// ticks of four seconds since Unix time.
// If the current time is not between the expiration time minus 16 seconds and the expiration time,
// an error is returned.
func CreateTsRel(expirationTick uint32, now time.Time) (uint32, error) {
	expiration := util.SecsToTime(TickDuration * expirationTick)
	timestamp := expiration.Add(-ExpirationOffset)
	if now.After(expiration) {
		return 0, serrors.New("provided packet expiration time is in the past",
			"expiration", expiration, "now", now)
	}
	if now.Before(timestamp) {
		return 0, serrors.New("provided packet expiration time is too far in the future",
			"timestamp", timestamp, "now", now)
	}
	diff := now.Sub(timestamp)
	tsRel := uint32(diff / TimestampResolution)
	return tsRel, nil
}

// VerifyExpirationTick returns whether the expiration time has not been reached yet.
func VerifyExpirationTick(expirationTick uint32) bool {
	expTime := TickDuration * int64(expirationTick)
	now := time.Now().Unix()
	return now <= expTime
}

// VerifyTimestamp checks whether a COLIBRI packet is fresh. This means that the time the packet
// was sent from the source host, which is encoded by the expiration tick and the Timestamp,
// does not date back more than the maximal packet lifetime of two seconds. The function also takes
// a possible clock drift between the packet source and the verifier of up to one second into
// account.
func VerifyTimestamp(expirationTick uint32, ts colibri.Timestamp, now time.Time) bool {
	tsRel, _, _ := ParseColibriTimestamp(ts)
	expiration := util.SecsToTime(TickDuration * expirationTick)
	diff := time.Duration(tsRel) * TimestampResolution
	tsSender := expiration.Add(-ExpirationOffset).Add(diff)

	if now.Before(tsSender.Add(-clockSkew)) ||
		now.After(tsSender.Add(packetLifetime).Add(clockSkew)) {

		return false
	}
	return true
}

// VerifyMAC verifies the authenticity of the MAC in the colibri hop field. If the MAC is correct,
// nil is returned, otherwise VerifyMAC returns an error.
func VerifyMAC(privateKey cipher.Block, ts colibri.Timestamp, inf *colibri.InfoField,
	currHop *colibri.HopField, s *slayers.SCION) error {

	var mac [4]byte
	var err error

	switch inf.C {
	case true:
		err = MACStatic(mac[:], privateKey, inf, currHop, s.SrcIA.AS(), s.DstIA.AS())
	case false:
		// TODO(juagargi) we will use the defined MAC computation once we start timestamping
		// the E2E colibri packets. For now do as if C=true. Toggle comments below.
		err = MACStatic(mac[:], privateKey, inf, currHop, s.SrcIA.AS(), s.DstIA.AS())
		// err = MACE2E(mac[:], privateKey, inf, ts, currHop, s)
	}
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(mac[:4], currHop.Mac[:4]) != 1 {
		return serrors.New("colibri mac verification failed",
			"calculated", hex.EncodeToString(mac[:4]),
			"packet", hex.EncodeToString(currHop.Mac[:4]))
	}
	return nil
}

// MACInputStatic prepares the buffer using the passed parameters to be used as input for the
// static MAC computation.
// buffer is expected to be at least `LengthInputData` bytes long.
// suffix is expected to be at most 12 byte long.
func MACInputStatic(buffer []byte, suffix []byte, expTick uint32,
	bwCls reservation.BWCls, rlc reservation.RLC, controlFlag, reverseFlag bool,
	idx reservation.IndexNumber, srcAS, dstAS addr.AS, ingress, egress uint16) {

	_ = buffer[LengthInputData-1]
	var zeroesBuff [12]byte
	copy(buffer[:12], zeroesBuff[:])
	copy(buffer[:12], suffix)
	binary.BigEndian.PutUint32(buffer[12:16], expTick)
	buffer[16] = uint8(bwCls)
	buffer[17] = uint8(rlc)
	buffer[18] = 0

	// Version | C | 0
	var flags uint8
	if controlFlag {
		flags = uint8(1) << 3
	}
	flags |= uint8(idx) << 4
	buffer[19] = flags
	if reverseFlag {
		srcAS = dstAS
		ingress, egress = egress, ingress
	}
	binary.BigEndian.PutUint64(buffer[22:30], uint64(srcAS))
	binary.BigEndian.PutUint16(buffer[20:22], ingress)
	binary.BigEndian.PutUint16(buffer[22:24], egress)
}

// MACStaticFromInput computes the colibri static MAC and writes it into buffer. If buffer is not at
// at least 4 bytes long, the functions panics at runtime.
// input is LengthInputDataRound16 bytes long.
// TODO(juagargi) move these buffer signatures to arrays with go 1.17 (whenever the compiler
// stops crashing with the slice->array casts).
func MACStaticFromInput(buffer []byte, key cipher.Block, input []byte) error {
	_ = buffer[3]
	// Initialize cryptographic MAC function
	f, err := initColibriMac(key)
	if err != nil {
		return err
	}
	// Calculate CBC-MAC = first 4 bytes of the last CBC block
	var mac [LengthInputDataRound16]byte
	f.CryptBlocks(mac[:], input)
	copy(buffer, mac[len(mac)-aes.BlockSize:len(mac)-aes.BlockSize+4])
	return nil
}

// MACStatic uses the functions MACInputStatic and
// MACStaticFromInput to compute the MAC.
func MACStatic(buffer []byte, privateKey cipher.Block, inf *colibri.InfoField,
	currHop *colibri.HopField, srcAS, dstAS addr.AS) error {

	var input [LengthInputDataRound16]byte
	MACInputStatic(input[:], inf.ResIdSuffix, inf.ExpTick, reservation.BWCls(inf.BwCls),
		reservation.RLC(inf.Rlc), inf.C, inf.R, reservation.IndexNumber(inf.Ver), srcAS, dstAS,
		currHop.IngressId, currHop.EgressId)
	return MACStaticFromInput(buffer, privateKey, input[:])
}

// MACSigma calculates the "sigma" authenticator, and
// writes it in buffer, which must be at least 16 bytes long (or runtime panic).
func MACSigma(buffer []byte, privateKey cipher.Block, inf *colibri.InfoField,
	currHop *colibri.HopField, s *slayers.SCION) error {

	_ = buffer[15]
	// Initialize cryptographic MAC function
	f, err := initColibriMac(privateKey)
	if err != nil {
		return err
	}
	// Prepare the input for the MAC function
	var input [64]byte
	inLen, err := MACInputSigma(input[:], s, inf, currHop)
	if err != nil {
		return err
	}

	// Calculate CBC-MAC = last CBC block
	mac := make([]byte, inLen)
	f.CryptBlocks(mac, input[:inLen])
	copy(buffer, mac[inLen-aes.BlockSize:])
	return nil
}

// MACE2E calculates the per-packet colibri MAC from the AS' private key and writes it into buffer.
// If buffer is not at least 4 bytes long, the function panics at runtime.
func MACE2E(buffer []byte, privateKey cipher.Block, inf *colibri.InfoField, ts colibri.Timestamp,
	currHop *colibri.HopField, s *slayers.SCION) error {

	var sigma [16]byte
	err := MACSigma(sigma[:], privateKey, inf, currHop, s)
	if err != nil {
		return err
	}

	// Initialize sigma
	keySigma, err := InitColibriKey(sigma[:])
	if err != nil {
		return err
	}

	return MACE2EFromSigma(buffer, keySigma, inf, ts, s)
}

// MACE2EFromSigma calculates the per-packet colibri MAC from sigma and writes it into buffer.
// If buffer is not at least 4 bytes long, the function panics at runtime.
func MACE2EFromSigma(buffer []byte, sigma cipher.Block, inf *colibri.InfoField,
	ts colibri.Timestamp, s *slayers.SCION) error {

	// Initialize cryptographic MAC function
	f, err := initColibriMac(sigma)
	if err != nil {
		return err
	}
	// Prepare the input for the MAC function
	var input [16]byte
	err = MACInputE2E(input[:], ts, inf, s)
	if err != nil {
		return err
	}

	// Calculate CBC-MAC = first 4 bytes of the last CBC block
	mac := make([]byte, len(input))
	f.CryptBlocks(mac, input[:])
	copy(buffer[:4], mac[len(mac)-aes.BlockSize:len(mac)-12])
	return nil
}

// InitColibriKey creates a new AES block cipher associated with the provided key.
func InitColibriKey(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.New("Unable to initialize AES cipher", "key", key)
	}
	return block, nil
}

func initColibriMac(key cipher.Block) (cipher.BlockMode, error) {
	// CBC-MAC = CBC-Encryption with zero initialization vector
	mode := cipher.NewCBCEncrypter(key, zeroInitVector[:])
	return mode, nil
}

// MACInputSigma copies the sigma function input values into the buffer,
// and the function returns its length.
// The buffer must be at least 64 bytes long, or a runtime panic will be issued.
// 64 = 30 (standard MAC input) + 1 (flags) + 16 (max src len) + 16 (dst); aligned to 16 bytes.
func MACInputSigma(buffer []byte, s *slayers.SCION, inf *colibri.InfoField,
	hop *colibri.HopField) (int, error) {

	_ = buffer[63]
	// prepare forward or reverse fields
	srcAddrType, dstAddrType := s.SrcAddrType, s.DstAddrType
	srcAddrLen, dstAddrLen := s.SrcAddrLen, s.DstAddrLen
	rawSrcAddr, rawDstAddr := s.RawSrcAddr, s.RawDstAddr
	if inf.R {
		srcAddrType, dstAddrType = dstAddrType, srcAddrType
		srcAddrLen, dstAddrLen = dstAddrLen, srcAddrLen
		rawSrcAddr, rawDstAddr = rawDstAddr, rawSrcAddr
	}
	// Check consistency of SL and DL with the actual address lengths
	srcLen := len(rawSrcAddr) // max 16 bytes
	dstLen := len(rawDstAddr)
	consistent := (4*(int(dstAddrLen)+1) == dstLen) &&
		(4*(int(srcAddrLen)+1) == srcLen)
	if !consistent {
		panic(fmt.Sprintf("SL/DL not consistent with actual address lengths. DL: %d, SL: %d",
			dstAddrLen, srcAddrLen))
	}

	// Write SL/ST/DL/DT into one single byte
	flags := uint8(dstAddrType&0x3)<<6 | uint8(dstAddrLen&0x3)<<4 |
		uint8(srcAddrType&0x3)<<2 | uint8(srcAddrLen&0x3)

	// The MAC input consists of the InputData plus the host addresses and the flags, rounded
	// up to the next multiple of aes.BlockSize bytes
	bufLen := LengthInputData + 1 + srcLen + dstLen
	nrBlocks := (bufLen-1)/aes.BlockSize + 1
	inputLen := aes.BlockSize * nrBlocks

	MACInputStatic(buffer[:], inf.ResIdSuffix, inf.ExpTick, reservation.BWCls(inf.BwCls),
		reservation.RLC(inf.Rlc), inf.C, inf.R, reservation.IndexNumber(inf.Ver),
		s.SrcIA.AS(), s.DstIA.AS(), hop.IngressId, hop.EgressId)
	buffer[LengthInputData] = flags
	copy(buffer[LengthInputData+1:], rawSrcAddr)
	copy(buffer[LengthInputData+1+srcLen:], rawDstAddr)

	return inputLen, nil
}

// MACInputE2E prepares the input for an e2e packet, and copies it into buffer.
// buffer must be at least 16 bytes long.
func MACInputE2E(buffer []byte, ts colibri.Timestamp, inf *colibri.InfoField,
	s *slayers.SCION) error {

	_ = buffer[15]
	copy(buffer[:8], ts[:])

	baseHdrLen := uint64(slayers.CmnHdrLen + s.AddrHdrLen())
	hfcount := uint64(inf.HFCount)
	colHdrLen := 32 + (hfcount * 8)
	payloadLen := uint64(inf.OrigPayLen)
	total64 := baseHdrLen + colHdrLen + payloadLen
	if total64 > (1 << 16) {
		return serrors.New("total packet length bigger than 2^16")
	}
	total16 := uint16(total64)

	binary.BigEndian.PutUint16(buffer[8:10], total16)
	return nil
}
