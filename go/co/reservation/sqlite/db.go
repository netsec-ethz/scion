// Copyright 2020 ETH Zurich, Anapaya Systems
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

package sqlite

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/segment"
	"github.com/scionproto/scion/go/co/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

type Backend struct {
	*executor
	db *sql.DB
}

var _ backend.DB = (*Backend)(nil)

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return nil, err
	}
	return &Backend{
		executor: &executor{
			db: db,
		},
		db: db,
	}, nil
}

// SetMaxOpenConns sets the maximum number of open connections.
func (b *Backend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}

// SetMaxIdleConns sets the maximum number of idle connections.
func (b *Backend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}

// BeginTransaction begins a transaction on the database.
func (b *Backend) BeginTransaction(ctx context.Context, opts *sql.TxOptions) (
	backend.Transaction, error) {

	// get a transaction that will try hard to be promoted to a write-transaction even in the
	// event of other write-transaction being present
	return NewTransaction(ctx,
		func() (*sql.Tx, error) {
			return b.db.BeginTx(ctx, opts)
		}, 100, 10*time.Millisecond)
}

// Close closes the databse.
func (b *Backend) Close() error {
	return b.db.Close()
}

type executor struct {
	db db.Sqler
}

func (x *executor) GetSegmentRsvFromID(ctx context.Context, ID *reservation.ID) (
	*segment.Reservation, error) {

	if !ID.IsSegmentID() {
		return nil, serrors.New("wrong suffix", "suffix", hex.EncodeToString(ID.Suffix))
	}
	params := []interface{}{
		ID.ASID,
		binary.BigEndian.Uint32(ID.Suffix),
	}
	rsvs, err := getSegReservations(ctx, x.db, "WHERE id_as = ? AND id_suffix = ?", params...)
	if err != nil {
		return nil, err
	}
	switch len(rsvs) {
	case 0:
		return nil, nil
	case 1:
		return rsvs[0], nil
	default:
		return nil, db.NewDataError("more than 1 segment reservation found for an ID", nil,
			"count", len(rsvs), "id.asid", ID.ASID, "id.suffix", hex.EncodeToString(ID.Suffix))
	}
}

// GetSegmentRsvsFromSrcDstIA returns all reservations that start at src AS and end in dst AS.
// Both srcIA and dstIA can use wildcards: 1-0, 0-ff00:1:1, or 0-0 are valid.
// The path type is optional: if not UnknownPath, it will match against it.
func (x *executor) GetSegmentRsvsFromSrcDstIA(ctx context.Context, srcIA, dstIA addr.IA,
	pathType reservation.PathType) ([]*segment.Reservation, error) {

	conditions, params := conditionsForIA(iaCond{"src_ia", srcIA}, iaCond{"dst_ia", dstIA})
	if len(conditions) == 0 {
		return nil, serrors.New("no src or dst ia provided")
	}
	if pathType != reservation.UnknownPath {
		conditions = append(conditions, "path_type = ?")
		params = append(params, pathType)
	}
	condition := fmt.Sprintf("WHERE %s", strings.Join(conditions, " AND "))
	return getSegReservations(ctx, x.db, condition, params...)
}

// GetAllSegmentRsvs returns all segment reservations.
func (x *executor) GetAllSegmentRsvs(ctx context.Context) ([]*segment.Reservation, error) {
	return getSegReservations(ctx, x.db, "")
}

// GetSegmentRsvsFromIFPair returns all segment reservations that enter this AS at
// the specified ingress and exit at that egress.
func (x *executor) GetSegmentRsvsFromIFPair(ctx context.Context, ingress, egress *uint16) (
	[]*segment.Reservation, error) {

	conditions := make([]string, 0, 2)
	params := make([]interface{}, 0, 2)
	if ingress != nil {
		conditions = append(conditions, "ingress = ?")
		params = append(params, *ingress)
	}
	if egress != nil {
		conditions = append(conditions, "egress = ?")
		params = append(params, *egress)
	}
	if len(conditions) == 0 {
		return nil, serrors.New("no ingress or egress provided")
	}
	condition := fmt.Sprintf("WHERE %s", strings.Join(conditions, " AND "))
	return getSegReservations(ctx, x.db, condition, params...)
}

// NewSegmentRsv creates a new segment reservation in the DB, with an unused reservation ID.
// The reservation must contain at least one index.
// The created ID is set in the reservation pointer argument.
func (x *executor) NewSegmentRsv(ctx context.Context, rsv *segment.Reservation) error {
	var err error
	for retries := 0; retries < 3; retries++ {
		err = db.DoInTx(ctx, x.db, func(ctx context.Context, tx *sql.Tx) error {
			suffix, err := newSegSuffix(ctx, tx, rsv.ID.ASID)
			if err != nil {
				return err
			}
			rsv.ID.Suffix = make([]byte, reservation.IDSuffixSegLen)
			binary.BigEndian.PutUint32(rsv.ID.Suffix, suffix)
			// the call to newSuffix guarantees this will be an insert
			if err := upsertNewSegReservation(ctx, tx, rsv); err != nil {
				return err
			}
			return nil
		})
		if err == nil {
			return nil
		}
		sqliteError, ok := err.(sqlite3.Error)
		if !ok || sqliteError.Code != sqlite3.ErrConstraint {
			return db.NewTxError("error inserting segment reservation", err)
		}
	}
	return db.NewTxError("error inserting segment reservation after 3 retries", err)
}

func (x *executor) PersistSegmentRsv(ctx context.Context, rsv *segment.Reservation) error {
	if !rsv.ID.IsSegmentID() {
		return serrors.New("wrong suffix", "suffix", hex.EncodeToString(rsv.ID.Suffix))
	}

	return upsertNewSegReservation(ctx, x.db, rsv)
}

// DeleteExpiredIndices will remove expired indices from the DB. If a reservation is left
// without any index after removing the expired ones, it will also be removed. This applies to
// both segment and e2e reservations.
func (x *executor) DeleteExpiredIndices(ctx context.Context, now time.Time) (int, error) {
	deletedIndices := 0
	err := db.DoInTx(ctx, x.db, func(ctx context.Context, tx *sql.Tx) error {
		// delete e2e indices
		rowIDs, rsvRowIDs, err := getExpiredE2EIndexRowIDs(ctx, tx, now)
		if err != nil {
			return err
		}
		if len(rowIDs) > 0 {
			// delete the segment indices pointed by rowIDs
			n, err := deleteE2EIndicesFromRowIDs(ctx, tx, rowIDs)
			if err != nil {
				return err
			}
			deletedIndices = n
			// delete empty reservations touched by previous removal
			err = deleteEmptyE2EReservations(ctx, tx, rsvRowIDs)
			if err != nil {
				return err
			}
		}

		// delete segment indices
		rowIDs, rsvRowIDs, err = getExpiredSegIndexRowIDs(ctx, tx, now)
		if err != nil {
			return err
		}
		if len(rowIDs) > 0 {
			cond := fmt.Sprintf("WHERE ROWID IN (?%s)", strings.Repeat(",?", len(rsvRowIDs)-1))
			affectedSegRsvs, err := getSegReservations(ctx, tx, cond, rsvRowIDs...)
			if err != nil {
				return err
			}
			previous := make(map[string]uint64, len(affectedSegRsvs))
			for _, seg := range affectedSegRsvs {
				previous[seg.ID.String()] = seg.MaxBlockedBW()
			}
			// delete the segment indices pointed by rowIDs
			n, err := deleteSegIndicesFromRowIDs(ctx, tx, rowIDs)
			if err != nil {
				return err
			}
			deletedIndices += n
			// update state of interfaces (used bandwidth may have changed)
			affectedSegRsvs, err = getSegReservations(ctx, tx, cond, rsvRowIDs...)
			if err != nil {
				return err
			}
			if len(affectedSegRsvs) != len(previous) {
				return serrors.New("error getting difference in bandwidth use while "+
					"expiring indices", "len_curr", len(affectedSegRsvs), "len_prev", len(previous))
			}
			ingressIFs := make(map[uint16]int64)
			egressIFs := make(map[uint16]int64)
			for _, seg := range affectedSegRsvs {
				curr := seg.MaxBlockedBW()
				prev := previous[seg.ID.String()]
				if curr != prev {
					diff := int64(prev - curr)
					ingressIFs[seg.Ingress] += diff
					egressIFs[seg.Egress] += diff
				}
			}
			for ifid, diff := range ingressIFs {
				err := interfaceStateUsedBWUpdate(ctx, tx, "state_ingress_interface", ifid, diff)
				if err != nil {
					return err
				}
			}
			for ifid, diff := range egressIFs {
				err := interfaceStateUsedBWUpdate(ctx, tx, "state_egress_interface", ifid, diff)
				if err != nil {
					return err
				}
			}
			// delete empty reservations touched by previous removal
			return deleteEmptySegReservations(ctx, tx, rsvRowIDs)
		}
		return nil
	})
	return deletedIndices, err
}

func (x *executor) NextExpirationTime(ctx context.Context) (time.Time, error) {
	var expSeg, expE2E uint32
	row := x.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(expiration),0xFFFFFFFF) FROM e2e_index`)
	if err := row.Scan(&expE2E); err != nil {
		return time.Time{}, err
	}
	row = x.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(expiration),0xFFFFFFFF) FROM seg_index`)
	if err := row.Scan(&expSeg); err != nil {
		return time.Time{}, err
	}
	expiration := expE2E
	if expiration == uint32(math.MaxUint32) || expSeg < expiration {
		expiration = expSeg
	}
	if expiration == uint32(math.MaxUint32) {
		expiration = 0
	}
	if expiration == 0 {
		return time.Time{}, nil
	}
	return util.SecsToTime(expiration), nil
}

// DeleteSegmentRsv removes the segment reservation
func (x *executor) DeleteSegmentRsv(ctx context.Context, ID *reservation.ID) error {
	return deleteSegmentRsv(ctx, x.db, ID)
}

// DeleteE2ERsv removes the e2e reservation
func (x *executor) DeleteE2ERsv(ctx context.Context, ID *reservation.ID) error {
	return deleteE2ERsv(ctx, x.db, ID)
}

func (x *executor) GetAllE2ERsvs(ctx context.Context) ([]*e2e.Reservation, error) {
	const query = `SELECT ROWID, reservation_id, steps, current_step FROM e2e_reservation`
	rows, err := x.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type rowFields struct {
		rowID       int
		rsvID       *reservation.ID
		currentStep int
		steps       base.PathSteps
	}
	fields := make([]rowFields, 0)
	for rows.Next() {
		var rowID int
		var rsvID []byte
		var rawSteps []byte
		var currentStep int
		if err := rows.Scan(&rowID, &rsvID, &rawSteps, &currentStep); err != nil {
			return nil, err
		}
		ID, err := reservation.IDFromRaw(rsvID)
		if err != nil {
			return nil, err
		}
		steps := base.PathStepsFromRaw(rawSteps)
		fields = append(fields, rowFields{
			rowID:       rowID,
			rsvID:       ID,
			currentStep: currentStep,
			steps:       steps,
		})
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	rsvs := make([]*e2e.Reservation, len(fields))
	for i, f := range fields {
		indices, err := getE2EIndices(ctx, x.db, f.rowID)
		if err != nil {
			return nil, err
		}
		// sort indices so they are consecutive modulo 16
		base.SortIndices(indices)
		// read assoc segment reservations
		segRsvs, err := getE2EAssocSegRsvs(ctx, x.db, f.rowID)
		if err != nil {
			return nil, err
		}
		rsvs[i] = &e2e.Reservation{
			ID:                  *f.rsvID,
			Steps:               f.steps,
			CurrentStep:         f.currentStep,
			Indices:             indices,
			SegmentReservations: segRsvs,
		}
	}
	return rsvs, nil
}

// GetE2ERsvFromID finds the end to end resevation given its ID.
func (x *executor) GetE2ERsvFromID(ctx context.Context, ID *reservation.ID) (
	*e2e.Reservation, error) {

	return getE2ERsvFromID(ctx, x.db, ID)
}

// GetE2ERsvsOnSegRsv returns the e2e reservations running on top of a given segment one.
func (x *executor) GetE2ERsvsOnSegRsv(ctx context.Context, ID *reservation.ID) (
	[]*e2e.Reservation, error) {

	return getE2ERsvsFromSegment(ctx, x.db, ID)
}

func (x *executor) PersistE2ERsv(ctx context.Context, rsv *e2e.Reservation) error {
	err := db.DoInTx(ctx, x.db, func(ctx context.Context, tx *sql.Tx) error {
		err := deleteE2ERsv(ctx, tx, &rsv.ID)
		if err != nil {
			return err
		}
		return insertNewE2EReservation(ctx, tx, rsv)
	})
	if err != nil {
		return db.NewTxError("error persisting e2e reservation", err)
	}
	return nil
}

func (x *executor) GetInterfaceUsageIngress(ctx context.Context, ifid uint16) (uint64, error) {
	return getInterfaceUsage(ctx, x.db, "state_ingress_interface", ifid)
}

func (x *executor) GetInterfaceUsageEgress(ctx context.Context, ifid uint16) (uint64, error) {
	return getInterfaceUsage(ctx, x.db, "state_egress_interface", ifid)
}

func (x *executor) GetTransitDem(ctx context.Context, ingress, egress uint16) (uint64, error) {
	return getTransitDem(ctx, x.db, ingress, egress)
}

func (x *executor) PersistTransitDem(ctx context.Context, ingress, egress uint16,
	transit uint64) error {

	return persistTransitDem(ctx, x.db, ingress, egress, transit)
}

func (x *executor) GetTransitAlloc(ctx context.Context, ingress, egress uint16) (uint64, error) {
	query := `SELECT traffic_alloc FROM state_transit_alloc
	WHERE ingress = ? AND egress = ?`
	var sum uint64
	if err := x.db.QueryRowContext(ctx, query, ingress, egress).Scan(&sum); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, serrors.WrapStr("get transit alloc failed", err)
	}
	return sum, nil
}

func (x *executor) PersistTransitAlloc(ctx context.Context, ingress, egress uint16,
	transit uint64) error {

	query := `INSERT INTO state_transit_alloc (ingress, egress, traffic_alloc)
			VALUES(?, ?, ?)
			ON CONFLICT(ingress,egress) DO UPDATE
			SET traffic_alloc = ?`
	_, err := x.db.ExecContext(ctx, query, ingress, egress, transit, transit)
	return err
}

func (x *executor) GetSourceState(ctx context.Context, source addr.AS, ingress, egress uint16) (
	uint64, uint64, error) {

	query := `SELECT src_demand,src_alloc FROM state_source_ingress_egress
	WHERE source = ? AND ingress = ? AND egress = ?`
	var srcDem, srcAlloc uint64
	if err := x.db.QueryRowContext(ctx, query, source, ingress, egress).Scan(
		&srcDem, &srcAlloc); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, nil
		}
		return 0, 0, serrors.WrapStr("get source state failed", err)
	}
	return srcDem, srcAlloc, nil
}

func (x *executor) PersistSourceState(ctx context.Context, source addr.AS, ingress, egress uint16,
	srcDem, srcAlloc uint64) error {

	query := `INSERT INTO state_source_ingress_egress
		(source, ingress, egress, src_demand, src_alloc)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(source,ingress,egress) DO UPDATE
		SET src_demand = ?, src_alloc = ?`
	_, err := x.db.ExecContext(ctx, query, source, ingress, egress, srcDem, srcAlloc,
		srcDem, srcAlloc)
	return err
}

func (x *executor) GetInDemand(ctx context.Context, source addr.AS, ingress uint16) (
	uint64, error) {

	query := `SELECT demand FROM state_source_ingress
		WHERE source = ? AND ingress = ?`
	var demand uint64
	if err := x.db.QueryRowContext(ctx, query, source, ingress).Scan(&demand); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, serrors.WrapStr("get in demand failed", err)
	}
	return demand, nil
}

func (x *executor) PersistInDemand(ctx context.Context, source addr.AS, ingress uint16,
	demand uint64) error {

	query := `INSERT INTO state_source_ingress (source, ingress, demand)
				VALUES(?, ?, ?)
				ON CONFLICT(source,ingress) DO UPDATE
				SET demand = ?`
	_, err := x.db.ExecContext(ctx, query, source, ingress, demand, demand)
	return err
}

func (x *executor) GetEgDemand(ctx context.Context, source addr.AS, egress uint16) (
	uint64, error) {

	query := `SELECT demand FROM state_source_egress
		WHERE source = ? AND egress = ?`
	var demand uint64
	if err := x.db.QueryRowContext(ctx, query, source, egress).Scan(&demand); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, serrors.WrapStr("get eg demand failed", err)
	}
	return demand, nil
}

func (x *executor) PersistEgDemand(ctx context.Context, source addr.AS, egress uint16,
	demand uint64) error {

	query := `INSERT INTO state_source_egress (source, egress, demand)
				VALUES(?, ?, ?)
				ON CONFLICT(source,egress) DO UPDATE
				SET demand = ?`
	_, err := x.db.ExecContext(ctx, query, source, egress, demand, demand)
	return err
}

func (x *executor) AddToAdmissionList(ctx context.Context, validUntil time.Time,
	dstEndhost net.IP, regexpIA, regexpHost string, allowAdmission bool) error {

	// first validate regular expressions
	if _, err := regexp.Compile(regexpIA); err != nil {
		return serrors.WrapStr("invalid IA regexp", err)
	}
	if _, err := regexp.Compile(regexpHost); err != nil {
		return serrors.WrapStr("invalid host regexp", err)
	}

	const query = `INSERT INTO e2e_admission_list (owner_host, valid_until,
		regexp_ia, regexp_host, yes_no) VALUES (?, ?, ?, ?, ?)`
	_, err := x.db.ExecContext(ctx, query,
		dstEndhost,
		util.TimeToSecs(validUntil),
		regexpIA,
		regexpHost,
		allowAdmission)

	return err
}
func (x *executor) CheckAdmissionList(ctx context.Context, now time.Time,
	dstEndhost net.IP, srcIA addr.IA, srcEndhost string) (int, error) {

	// all entries that belong to dstEndhost sorted by the order they where added (newest first)
	const query = `SELECT valid_until, regexp_ia, regexp_host, yes_no FROM e2e_admission_list
		WHERE owner_host = ? ORDER BY ROWID DESC`

	rows, err := x.db.QueryContext(ctx, query, dstEndhost)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var validUntilSecs int32
		var regexpIA, regexpHost string
		var accepted bool

		err = rows.Scan(&validUntilSecs, &regexpIA, &regexpHost, &accepted)
		if err != nil {
			return 0, serrors.WrapStr("obtaining the admission list", err)
		}
		validUntil := util.SecsToTime(uint32(validUntilSecs))
		if now.After(validUntil) {
			continue
		}
		if match, _ := regexp.MatchString(regexpIA, srcIA.String()); !match {
			continue
		}
		if match, _ := regexp.MatchString(regexpHost, srcEndhost); !match {
			continue
		}
		if accepted {
			return 1, nil
		} else {
			return -1, nil
		}
	}
	if rows.Err() != nil {
		return 0, rows.Err()
	}
	return 0, nil
}

func (x *executor) DeleteExpiredAdmissionEntries(ctx context.Context, now time.Time) (int, error) {
	const query = `DELETE FROM e2e_admission_list WHERE valid_until > ?`
	res, err := x.db.ExecContext(ctx, query, util.TimeToSecs(now))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func (x *executor) DebugCountSegmentRsvs(ctx context.Context) (int, error) {
	const query = `SELECT COUNT(*) FROM seg_reservation`
	var count int
	err := x.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (x *executor) DebugCountE2ERsvs(ctx context.Context) (int, error) {
	const query = `SELECT COUNT(*) FROM e2e_reservation`
	var count int
	err := x.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// newSegSuffix finds a segment reservation ID suffix not being used at the moment. Should be called
// inside a transaction so the suffix is not used in the meantime, or fail.
func newSegSuffix(ctx context.Context, x db.Sqler, ASID addr.AS) (uint32, error) {
	const query = `SELECT COALESCE(MAX(id_suffix), 0) + 1
		FROM	seg_reservation sr
		WHERE	sr.id_as = ?`
	var suffix uint32
	err := x.QueryRowContext(ctx, query, uint64(ASID)).Scan(&suffix)
	switch {
	case err == sql.ErrNoRows:
		return 0, serrors.New("unexpected error getting new suffix: no rows")
	case err != nil:
		return 0, serrors.WrapStr("unexpected error getting new suffix", err)
	}
	return suffix, nil
}

// TODO(juagargi) force signature of those methods that write several times to DB to
// take a transaction instead of Sqler, to ensure atomicity.
func upsertNewSegReservation(ctx context.Context, x db.Sqler, rsv *segment.Reservation) error {
	activeIndex := -1
	if rsv.ActiveIndex() != nil {
		activeIndex = int(rsv.ActiveIndex().Idx)
	}

	err := deleteStateForRsv(ctx, x, &rsv.ID)
	if err != nil {
		return err
	}
	rawSteps := rsv.Steps.ToRaw()
	rawPath, err := base.PathToRaw(rsv.TransportPath)
	if err != nil {
		return err
	}
	const query = `INSERT INTO seg_reservation (id_as, id_suffix,
		ingress, egress, path_type, steps, current_step, rawPath, end_props,
		traffic_split, src_ia, dst_ia, active_index)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id_as,id_suffix) DO UPDATE
		SET ingress = ?, egress = ?, path_type = ?, steps = ?, current_step = ?, rawPath = ?,
		end_props = ?, traffic_split = ?, src_ia = ?, dst_ia = ?, active_index = ?`
	_, err = x.ExecContext(
		ctx, query, rsv.ID.ASID, binary.BigEndian.Uint32(rsv.ID.Suffix), rsv.Ingress, rsv.Egress,
		rsv.PathType, rawSteps, rsv.CurrentStep, rawPath, rsv.PathEndProps, rsv.TrafficSplit, rsv.Steps.SrcIA(),
		rsv.Steps.DstIA(), activeIndex, rsv.Ingress, rsv.Egress, rsv.PathType, rawSteps, rsv.CurrentStep, rawPath,
		rsv.PathEndProps, rsv.TrafficSplit, rsv.Steps.SrcIA(), rsv.Steps.DstIA(), activeIndex)
	if err != nil {
		return err
	}
	// getting the rowID should have worked with result.LastInsertId(), but it doesn't (UT fail)
	var rsvRowID int64
	err = x.QueryRowContext(ctx,
		"SELECT ROWID FROM seg_reservation WHERE id_as = ? AND id_suffix = ?",
		rsv.ID.ASID, binary.BigEndian.Uint32(rsv.ID.Suffix)).Scan(&rsvRowID)
	if err != nil {
		return err
	}

	deleteQuery := `DELETE FROM seg_index WHERE reservation = ?`
	_, err = x.ExecContext(ctx, deleteQuery, rsvRowID)
	if err != nil {
		return err
	}

	if len(rsv.Indices) > 0 {
		const queryIndexTmpl = `INSERT INTO seg_index (reservation, index_number, expiration, state,
		min_bw, max_bw, alloc_bw, token) VALUES (?,?,?,?,?,?,?,?)`
		params := make([]interface{}, 0, 8*len(rsv.Indices))
		for _, index := range rsv.Indices {
			params = append(params, rsvRowID, index.Idx,
				util.TimeToSecs(index.Expiration), index.State, index.MinBW, index.MaxBW,
				index.AllocBW, index.Token.ToRaw())
			if _, err := reservation.TokenFromRaw(index.Token.ToRaw()); err != nil {
				log.Error("inconsistent token being saved", "err", err, "id", rsv.ID.String(),
					"idx", index.Idx)
			}
		}
		q := queryIndexTmpl + strings.Repeat(",(?,?,?,?,?,?,?,?)", len(rsv.Indices)-1)
		_, err = x.ExecContext(ctx, q, params...)
		if err != nil {
			return err
		}

		// update interface state
		blocked := int64(rsv.MaxBlockedBW())
		return interfacesStateUsedBWUpdate(ctx, x, rsv.Ingress, rsv.Egress, blocked)
	}
	return nil
}

type rsvFields struct {
	RowID        int
	AsID         uint64
	Suffix       uint32
	Ingress      uint16
	Egress       uint16
	PathType     int
	Steps        []byte
	CurrentStep  int
	RawPath      []byte
	EndProps     int
	TrafficSplit int
	ActiveIndex  int
}

func getSegReservations(ctx context.Context, x db.Sqler, condition string, params ...interface{}) (
	[]*segment.Reservation, error) {

	const queryTmpl = `SELECT ROWID,id_as,id_suffix,ingress,egress,path_type,steps,current_step,
		rawPath,end_props,traffic_split,active_index FROM seg_reservation %s`
	query := fmt.Sprintf(queryTmpl, condition)

	rows, err := x.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	reservationFields := []*rsvFields{}
	for rows.Next() {
		var f rsvFields
		err := rows.Scan(&f.RowID, &f.AsID, &f.Suffix, &f.Ingress, &f.Egress, &f.PathType, &f.Steps, &f.CurrentStep,
			&f.RawPath, &f.EndProps, &f.TrafficSplit, &f.ActiveIndex)
		if err != nil {
			return nil, err
		}
		reservationFields = append(reservationFields, &f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	reservations := []*segment.Reservation{}
	for _, rf := range reservationFields {
		rsv, err := buildSegRsvFromFields(ctx, x, rf)
		if err != nil {
			return nil, err
		}
		reservations = append(reservations, rsv)
	}
	return reservations, nil
}

// builds a segment.Reservation in memory from the fields and indices.
func buildSegRsvFromFields(ctx context.Context, x db.Sqler, fields *rsvFields) (
	*segment.Reservation, error) {

	indices, err := getSegIndices(ctx, x, fields.RowID)
	if err != nil {
		return nil, err
	}
	rsv := segment.NewReservation(addr.AS(fields.AsID))
	rsv.ID.Suffix = make([]byte, reservation.IDSuffixSegLen)
	binary.BigEndian.PutUint32(rsv.ID.Suffix, fields.Suffix)
	rsv.Ingress = fields.Ingress
	rsv.Egress = fields.Egress
	rsv.PathType = reservation.PathType(fields.PathType)

	steps := base.PathStepsFromRaw(fields.Steps)
	rawPath, err := base.PathFromRaw(fields.RawPath)
	if err != nil {
		return nil, err
	}
	rsv.Steps = steps
	rsv.CurrentStep = fields.CurrentStep
	rsv.TransportPath = rawPath
	rsv.PathEndProps = reservation.PathEndProps(fields.EndProps)
	rsv.TrafficSplit = reservation.SplitCls(fields.TrafficSplit)
	rsv.Indices = indices
	if fields.ActiveIndex != -1 {
		if err := rsv.SetIndexActive(reservation.IndexNumber(fields.ActiveIndex)); err != nil {
			return nil, err
		}
	}
	return rsv, nil
}

// the rowID argument is the reservation row ID the indices belong to.
func getSegIndices(ctx context.Context, x db.Sqler, rowID int) (segment.Indices, error) {
	const query = `SELECT index_number,expiration,state,min_bw,max_bw,alloc_bw,token
		FROM seg_index WHERE reservation=?`
	rows, err := x.QueryContext(ctx, query, rowID)
	if err != nil {
		return nil, db.NewReadError("cannot list indices", err)
	}
	defer rows.Close()

	indices := segment.Indices{}
	var idx, expiration, state, minBW, maxBW, allocBW uint32
	var token []byte
	for rows.Next() {
		err := rows.Scan(&idx, &expiration, &state, &minBW, &maxBW, &allocBW, &token)
		if err != nil {
			return nil, db.NewReadError("could not get index values", err)
		}
		tok, err := reservation.TokenFromRaw(token)
		if err != nil {
			return nil, db.NewReadError("invalid stored token", err)
		}
		index := segment.NewIndex(reservation.IndexNumber(idx),
			util.SecsToTime(expiration), segment.IndexState(state), reservation.BWCls(minBW),
			reservation.BWCls(maxBW), reservation.BWCls(allocBW), tok)
		indices = append(indices, *index)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// sort indices so they are consecutive modulo 16
	base.SortIndices(indices)
	return indices, nil
}

func deleteStateForRsv(ctx context.Context, x db.Sqler, rsvID *reservation.ID) error {
	// get blocked bandwidth to update the ingress/egress interfaces tables,
	// and all the state ones in general
	params := []interface{}{
		rsvID.ASID,
		binary.BigEndian.Uint32(rsvID.Suffix),
	}
	rsvs, err := getSegReservations(ctx, x, "WHERE id_as = ? AND id_suffix = ?", params...)
	if err != nil {
		return err
	}
	switch len(rsvs) {
	case 0:
	case 1:
		blocked := -int64(rsvs[0].MaxBlockedBW()) // more free bandwidth
		err := interfacesStateUsedBWUpdate(ctx, x, rsvs[0].Ingress, rsvs[0].Egress, blocked)
		if err != nil {
			return err
		}
		// err = subtractTransitDem(ctx, x, rsvs[0].Ingress, rsvs[0].Egress, uint64(blocked))
		// if err != nil {
		// 	return err
		// }
	default:
		return serrors.New("Got more than one reservation for one ID", "ID", rsvID.String())
	}
	return nil
}

func deleteSegmentRsv(ctx context.Context, x db.Sqler, rsvID *reservation.ID) error {
	if !rsvID.IsSegmentID() {
		return serrors.New("wrong suffix", "suffix", hex.EncodeToString(rsvID.Suffix))
	}

	err := deleteStateForRsv(ctx, x, rsvID)
	if err != nil {
		return err
	}
	// now remove the reservation
	const query = `DELETE FROM seg_reservation WHERE id_as = ? AND id_suffix = ?`
	suffix := binary.BigEndian.Uint32(rsvID.Suffix)
	_, err = x.ExecContext(ctx, query, rsvID.ASID, suffix)
	if err != nil {
		return err
	}
	return err
}

func deleteE2ERsv(ctx context.Context, x db.Sqler, rsvID *reservation.ID) error {
	const query = `DELETE FROM e2e_reservation WHERE reservation_id = ?`
	_, err := x.ExecContext(ctx, query, rsvID.ToRaw())
	return err
}

func insertNewE2EReservation(ctx context.Context, x *sql.Tx, rsv *e2e.Reservation) error {
	const query = `INSERT INTO e2e_reservation (reservation_id, steps, current_step)
	VALUES (?, ?, ?)`
	res, err := x.ExecContext(ctx, query, rsv.ID.ToRaw(), rsv.Steps.ToRaw(), rsv.CurrentStep)
	if err != nil {
		return err
	}
	rowID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if len(rsv.Indices) > 0 {
		const queryTmpl = `
		INSERT INTO e2e_index (reservation, index_number, expiration, alloc_bw, token)
		VALUES (?,?,?,?,?)`
		params := make([]interface{}, 0, 5*len(rsv.Indices))
		for _, index := range rsv.Indices {
			params = append(params, rowID, index.Idx, util.TimeToSecs(index.Expiration),
				index.AllocBW, index.Token.ToRaw())
		}
		query := queryTmpl + strings.Repeat(",(?,?,?,?,?)", len(rsv.Indices)-1)
		_, err := x.ExecContext(ctx, query, params...)
		if err != nil {
			return err
		}
	}
	if len(rsv.SegmentReservations) > 0 {
		const queryIns = "INSERT INTO e2e_to_seg (e2e, seg, ordr)\n"
		const segQuery = `SELECT ?, ROWID, ? FROM seg_reservation WHERE id_as = ? AND id_suffix = ?`

		query := queryIns + segQuery +
			strings.Repeat("\nUNION\n"+segQuery, len(rsv.SegmentReservations)-1)

		params := make([]interface{}, 0, 4*len(rsv.SegmentReservations))
		for i, segRsv := range rsv.SegmentReservations {
			params = append(params, rowID, i,
				segRsv.ID.ASID, binary.BigEndian.Uint32(segRsv.ID.Suffix))
		}
		res, err := x.ExecContext(ctx, query, params...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if int(n) != len(rsv.SegmentReservations) {
			return serrors.New("not all referenced segment reservations are in DB",
				"expected", len(rsv.SegmentReservations), "actual", n)
		}
	}
	return nil
}

func getE2ERsvFromID(ctx context.Context, x db.Sqler, ID *reservation.ID) (
	*e2e.Reservation, error) {

	// read reservation
	var rowID int
	var rawSteps []byte
	var currentStep int
	const query = `SELECT ROWID, steps, current_step FROM e2e_reservation WHERE reservation_id = ?`
	err := x.QueryRowContext(ctx, query, ID.ToRaw()).Scan(&rowID, &rawSteps, &currentStep)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	steps := base.PathStepsFromRaw(rawSteps)
	// read indices
	indices, err := getE2EIndices(ctx, x, rowID)
	if err != nil {
		return nil, err
	}
	// sort indices so they are consecutive modulo 16
	base.SortIndices(indices)
	// read assoc segment reservations
	segRsvs, err := getE2EAssocSegRsvs(ctx, x, rowID)
	if err != nil {
		return nil, err
	}
	rsv := &e2e.Reservation{
		ID:                  *ID.Copy(),
		Steps:               steps,
		CurrentStep:         currentStep,
		Indices:             indices,
		SegmentReservations: segRsvs,
	}
	return rsv, nil
}

func getE2ERsvsFromSegment(ctx context.Context, x db.Sqler, ID *reservation.ID) (
	[]*e2e.Reservation, error) {

	if !ID.IsSegmentID() {
		return nil, serrors.New("wrong suffix", "suffix", hex.EncodeToString(ID.Suffix))
	}
	rowID2e2eIDs := make(map[int]*e2e.Reservation)
	const query = `
	SELECT ROWID,reservation_id, steps, current_step FROM e2e_reservation
	WHERE ROWID IN (
		SELECT e2e FROM e2e_to_seg
		WHERE seg =  (
			SELECT ROWID FROM seg_reservation
			WHERE id_as = ? AND id_suffix = ?
		)
	)`
	suffix := binary.BigEndian.Uint32(ID.Suffix)
	rows, err := x.QueryContext(ctx, query, ID.ASID, suffix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rowID int
		var rsvID []byte
		var rawSteps []byte
		var currentStep int
		err := rows.Scan(&rowID, &rsvID, &rawSteps, &currentStep)
		if err != nil {
			return nil, err
		}
		id, err := reservation.IDFromRaw(rsvID)
		if err != nil {
			return nil, err
		}
		steps := base.PathStepsFromRaw(rawSteps)
		rowID2e2eIDs[rowID] = &e2e.Reservation{
			ID:          *id,
			Steps:       steps,
			CurrentStep: currentStep,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rsvs := make([]*e2e.Reservation, 0, len(rowID2e2eIDs))
	for rowID, rsv := range rowID2e2eIDs {
		// read indices
		indices, err := getE2EIndices(ctx, x, rowID)
		if err != nil {
			return nil, err
		}
		// read assoc segment reservations
		segRsvs, err := getE2EAssocSegRsvs(ctx, x, rowID)
		if err != nil {
			return nil, err
		}
		rsv.Indices = indices
		rsv.SegmentReservations = segRsvs
		rsvs = append(rsvs, rsv)
	}
	return rsvs, nil
}

func getE2EIndices(ctx context.Context, x db.Sqler, rowID int) (e2e.Indices, error) {
	const query = `SELECT index_number, expiration, alloc_bw, token FROM e2e_index
		WHERE reservation = ?`
	rows, err := x.QueryContext(ctx, query, rowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	indices := e2e.Indices{}
	for rows.Next() {
		var idx, expiration, allocBW uint32
		var token []byte
		err := rows.Scan(&idx, &expiration, &allocBW, &token)
		if err != nil {
			return nil, err
		}
		tok, err := reservation.TokenFromRaw(token)
		if err != nil {
			return nil, err
		}
		indices = append(indices, e2e.Index{
			Idx:        reservation.IndexNumber(idx),
			Expiration: util.SecsToTime(expiration),
			AllocBW:    reservation.BWCls(allocBW),
			Token:      tok,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return indices, nil
}

// rowID is the row ID of the E2E reservation
func getE2EAssocSegRsvs(ctx context.Context, x db.Sqler, rowID int) (
	[]*segment.Reservation, error) {

	condition := `JOIN e2e_to_seg ON e2e_to_seg.seg=ROWID WHERE e2e_to_seg.e2e=?
		ORDER BY e2e_to_seg.ordr ASC`
	return getSegReservations(ctx, x, condition, rowID)
}

// returns the rowIDs of the indices and their associated segment reservation rowID
func getExpiredSegIndexRowIDs(ctx context.Context, x db.Sqler, now time.Time) (
	[]interface{}, []interface{}, error) {

	const query = `SELECT rowID, reservation FROM seg_index WHERE expiration < ?`
	expTime := util.TimeToSecs(now)
	rows, err := x.QueryContext(ctx, query, expTime)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	rowIDs := make([]interface{}, 0)
	rsvRowIDs := make([]interface{}, 0)
	for rows.Next() {
		var indexID, rsvRowID int
		err := rows.Scan(&indexID, &rsvRowID)
		if err != nil {
			return nil, nil, err
		}
		rowIDs = append(rowIDs, indexID)
		rsvRowIDs = append(rsvRowIDs, rsvRowID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return rowIDs, rsvRowIDs, nil
}

func deleteSegIndicesFromRowIDs(ctx context.Context, x db.Sqler, rowIDs []interface{}) (
	int, error) {

	// check if any index is active, and change the reservation to no active index in that case
	query := `SELECT DISTINCT reservation FROM seg_index WHERE state = ? AND ROWID IN (?%s)`
	query = fmt.Sprintf(query, strings.Repeat(",?", len(rowIDs)-1))
	params := []interface{}{segment.IndexActive}
	rows, err := x.QueryContext(ctx, query, append(params, rowIDs...)...)
	if err != nil {
		return 0, err
	}

	rsvRowIds := make([]int, 0)
	for rows.Next() {
		var rsvRowId int
		if err := rows.Scan(&rsvRowId); err != nil {
			return 0, err
		}
		rsvRowIds = append(rsvRowIds, rsvRowId)
	}
	if len(rsvRowIds) > 0 {
		// need to update the active index
		query = `UPDATE seg_reservation SET active_index=-1 WHERE ROWID IN(?%s)`
		query = fmt.Sprintf(query, strings.Repeat(",?", len(rsvRowIds)-1))
		params := make([]interface{}, len(rsvRowIds))
		for i, id := range rsvRowIds {
			params[i] = id
		}
		res, err := x.ExecContext(ctx, query, params...)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if int(n) != len(rsvRowIds) {
			return 0, serrors.New(fmt.Sprintf("error updating active_index after deleting index; "+
				"updated %d reservations but wanted %d", n, len(rsvRowIds)))
		}
	}

	query = `DELETE FROM seg_index WHERE ROWID IN (?%s)`
	query = fmt.Sprintf(query, strings.Repeat(",?", len(rowIDs)-1))
	res, err := x.ExecContext(ctx, query, rowIDs...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// deletes segment reservations from the rowIDs if they have no indices
func deleteEmptySegReservations(ctx context.Context, x db.Sqler, rowIDs []interface{}) error {
	const queryTmpl = `DELETE FROM seg_reservation AS r WHERE NOT EXISTS (
		SELECT NULL FROM seg_index AS idx WHERE idx.reservation=r.ROWID
	) AND r.ROWID IN (?%s);`
	query := fmt.Sprintf(queryTmpl, strings.Repeat(",?", len(rowIDs)-1))
	_, err := x.ExecContext(ctx, query, rowIDs...)
	return err
}

func getExpiredE2EIndexRowIDs(ctx context.Context, x db.Sqler, now time.Time) (
	[]interface{}, []interface{}, error) {

	const query = `SELECT ROWID, reservation FROM e2e_index WHERE expiration < ?`
	expTime := util.TimeToSecs(now)
	rows, err := x.QueryContext(ctx, query, expTime)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	rowIDs := make([]interface{}, 0)
	rsvRowIDs := make([]interface{}, 0)
	for rows.Next() {
		var indexID, rsvRowID int
		err := rows.Scan(&indexID, &rsvRowID)
		if err != nil {
			return nil, nil, err
		}
		rowIDs = append(rowIDs, indexID)
		rsvRowIDs = append(rsvRowIDs, rsvRowID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return rowIDs, rsvRowIDs, nil
}

func deleteE2EIndicesFromRowIDs(ctx context.Context, x db.Sqler, rowIDs []interface{}) (
	int, error) {

	const queryTmpl = `DELETE FROM e2e_index WHERE ROWID IN (?%s)`
	query := fmt.Sprintf(queryTmpl, strings.Repeat(",?", len(rowIDs)-1))
	res, err := x.ExecContext(ctx, query, rowIDs...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// deletes e2e reservations from the rowIDs if they have no indices
func deleteEmptyE2EReservations(ctx context.Context, x db.Sqler, rowIDs []interface{}) error {
	const queryTmpl = `DELETE FROM e2e_reservation AS r WHERE NOT EXISTS (
		SELECT NULL FROM e2e_index AS idx WHERE idx.reservation=r.ROWID
	) AND r.ROWID IN (?%s);`
	query := fmt.Sprintf(queryTmpl, strings.Repeat(",?", len(rowIDs)-1))
	_, err := x.ExecContext(ctx, query, rowIDs...)
	return err
}

func getInterfaceUsage(ctx context.Context, x db.Sqler, table string, ifid uint16) (uint64, error) {
	query := fmt.Sprintf(`SELECT blocked_bw FROM %s WHERE ifid = ?`, table)
	var usedBW uint64
	err := x.QueryRowContext(ctx, query, ifid).Scan(&usedBW)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return usedBW, nil
}

func interfaceStateUsedBWUpdate(ctx context.Context, x db.Sqler,
	table string, ifid uint16, deltaBW int64) error {

	query := fmt.Sprintf(`INSERT INTO %s(ifid, blocked_bw) VALUES(?, ?)
	ON CONFLICT(ifid) DO UPDATE
	SET blocked_bw = blocked_bw + ?`, table)
	_, err := x.ExecContext(ctx, query, ifid, deltaBW, deltaBW)
	return err
}

func interfacesStateUsedBWUpdate(ctx context.Context, x db.Sqler, ingress, egress uint16,
	deltaBW int64) error {

	err := interfaceStateUsedBWUpdate(ctx, x, "state_ingress_interface", ingress, deltaBW)
	if err != nil {
		return err
	}
	return interfaceStateUsedBWUpdate(ctx, x, "state_egress_interface", egress, deltaBW)
}

func getTransitDem(ctx context.Context, x db.Sqler, ingress, egress uint16) (uint64, error) {

	query := `SELECT traffic_demand from state_transit_demand
	WHERE ingress = ? AND egress = ?`
	var transit uint64
	if err := x.QueryRowContext(ctx, query, ingress, egress).Scan(&transit); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, serrors.WrapStr("get transit demand failed", err,
			"ingress", ingress, "egress", egress)
	}
	return transit, nil
}

func persistTransitDem(ctx context.Context, x db.Sqler, ingress, egress uint16,
	transit uint64) error {

	query := `INSERT INTO state_transit_demand (ingress, egress, traffic_demand)
		VALUES(?, ?, ?)
		ON CONFLICT(ingress,egress) DO UPDATE
		SET traffic_demand = ?`
	_, err := x.ExecContext(ctx, query, ingress, egress, transit, transit)
	return err
}

func subtractTransitDem(ctx context.Context, x db.Sqler, ingress, egress uint16,
	dem uint64) error {

	balance, err := getTransitDem(ctx, x, ingress, egress)
	if err != nil {
		return err
	}
	if balance == 0 {
		return nil
	}
	var newDem uint64
	if balance > dem {
		newDem = balance - dem
	} else {
		newDem = 0
	}
	query := `UPDATE state_transit_demand SET traffic_demand=?
	WHERE ingress=? AND egress=?`
	_, err = x.ExecContext(ctx, query, newDem, ingress, egress)
	return err
}

type iaCond struct {
	fieldName  string
	fieldValue addr.IA
}

func conditionsForIA(pairs ...iaCond) ([]string, []interface{}) {
	conditions := make([]string, 0, len(pairs))
	params := make([]interface{}, 0, len(pairs))
	for _, pair := range pairs {
		if pair.fieldValue.IsZero() {
			continue
		}
		switch {
		case pair.fieldValue.ISD() == 0:
			conditions = append(conditions, pair.fieldName+" & 0x0000FFFFFFFFFFFF = ?")
			params = append(params, uint64(pair.fieldValue.AS()))
		case pair.fieldValue.AS() == 0:
			conditions = append(conditions, pair.fieldName+" & 0xFFFF000000000000 >> 48 = ?")
			params = append(params, uint64(pair.fieldValue.ISD()))
		default:
			conditions = append(conditions, pair.fieldName+" = ?")
			params = append(params, uint64(pair.fieldValue))
		}
	}
	return conditions, params
}
