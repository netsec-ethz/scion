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

const (
	// SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	SchemaVersion = 1
	// Schema is the SQLite database layout.
	Schema = `CREATE TABLE seg_reservation (
		ROWID	INTEGER,
		id_as	INTEGER NOT NULL,
		id_suffix	INTEGER NOT NULL,
		ingress	INTEGER NOT NULL,
		egress	INTEGER NOT NULL,
		path_type	INTEGER NOT NULL,
		steps BLOB,
		current_step INTEGER NOT NULL,
		transportPath BLOB,
		end_props	INTEGER NOT NULL,
		traffic_split	INTEGER NOT NULL,
		src_ia INTEGER,
		dst_ia INTEGER,
		active_index	INTEGER NOT NULL,
		PRIMARY KEY(ROWID),
		UNIQUE(id_as,id_suffix)
	);
	CREATE TABLE seg_index (
		reservation	INTEGER NOT NULL,
		index_number	INTEGER NOT NULL,
		expiration	INTEGER NOT NULL,
		state	INTEGER NOT NULL,
		min_bw	INTEGER NOT NULL,
		max_bw	INTEGER NOT NULL,
		alloc_bw	INTEGER NOT NULL,
		token	BLOB,
		PRIMARY KEY(reservation,index_number),
		FOREIGN KEY(reservation) REFERENCES seg_reservation(ROWID) ON DELETE CASCADE
	);
	CREATE TABLE e2e_reservation (
		ROWID	INTEGER,
		reservation_id	BLOB NOT NULL,
		steps	BLOB,
		current_step INTEGER,
		UNIQUE(reservation_id),
		PRIMARY KEY(ROWID)
	);
	CREATE TABLE e2e_index (
		reservation	INTEGER NOT NULL,
		index_number	INTEGER NOT NULL,
		expiration	INTEGER NOT NULL,
		alloc_bw	INTEGER NOT NULL,
		token	BLOB,
		PRIMARY KEY(reservation,index_number),
		FOREIGN KEY(reservation) REFERENCES e2e_reservation(ROWID) ON DELETE CASCADE
	);
	CREATE TABLE e2e_to_seg (
		e2e	INTEGER NOT NULL,
		seg	INTEGER NOT NULL,
		ordr INTEGER NOT NULL,
		PRIMARY KEY(e2e,seg),
		FOREIGN KEY(seg) REFERENCES seg_reservation(ROWID) ON DELETE CASCADE,
		FOREIGN KEY(e2e) REFERENCES e2e_reservation(ROWID) ON DELETE CASCADE
	);
	CREATE TABLE e2e_admission_list (
		ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
		owner_host BLOB NOT NULL,
		valid_until INTEGER NOT NULL,
		regexp_ia TEXT NOT NULL,
		regexp_host TEXT NOT NULL,
		yes_no INTEGER NOT NULL
	);

	-- Tables that start with state_ are meant to enhance performance.
	-- They must be updated every time an index / reservation is added / deleted / modified.

	-- state_ingress_interface keeps the blocked bandwidth per interface ID in this AS
	CREATE TABLE state_ingress_interface (
		ifid	INTEGER NOT NULL,
		blocked_bw	INTEGER NOT NULL,
		PRIMARY KEY(ifid)
	);
	CREATE TABLE state_egress_interface (
		ifid	INTEGER NOT NULL,
		blocked_bw	INTEGER NOT NULL,
		PRIMARY KEY(ifid)
	);

	-- state_transit_demand keeps the current transit demand between interface pairs.
	CREATE TABLE state_transit_demand (
		ingress INTEGER NOT NULL,
		egress  INTEGER NOT NULL,
		traffic_demand INTEGER NOT NULL,
		PRIMARY KEY(ingress,egress)
	);

	-- stores the sum of egScalFctr x srcAlloc for all sources, between interface pairs.
	-- It is essentially the denominator of the link ratio formula.
	CREATE TABLE state_transit_alloc (
		ingress INTEGER NOT NULL,
		egress INTEGER NOT NULL,
		traffic_alloc INTEGER NOT NULL,
		PRIMARY KEY(ingress,egress)
	);

	-- state_source_ingress_egress stores the source demands and allocations for a given
	-- source, and ingress and egress interfaces.
	CREATE TABLE state_source_ingress_egress (
		source INTEGER NOT NULL,
		ingress INTEGER NOT NULL,
		egress INTEGER NOT NULL,
		src_demand INTEGER NOT NULL,
		src_alloc INTEGER NOT NULL,
		PRIMARY KEY(source,ingress,egress)
	);

	-- stores inDemand for a given source and ingress interface.
	CREATE TABLE state_source_ingress (
		source INTEGER NOT NULL,
		ingress INTEGER NOT NULL,
		demand INTEGER NOT NULL,
		PRIMARY KEY(source,ingress)
	);

	-- stores egDemand for a given source and egress interface.
	CREATE TABLE state_source_egress (
		source INTEGER NOT NULL,
		egress INTEGER NOT NULL,
		demand INTEGER NOT NULL,
		PRIMARY KEY(source,egress)
	);


	CREATE INDEX "index_seg_reservation" ON "seg_reservation" (
		"id_as",
		"id_suffix"
	);
	CREATE INDEX "index2_seg_reservation" ON "seg_reservation" (
		"ingress"
	);
	CREATE INDEX "index3_seg_reservation" ON "seg_reservation" (
		"egress"
	);
	CREATE UNIQUE INDEX "index_seg_index" ON "seg_index" (
		"reservation",
		"index_number"
	);
	CREATE UNIQUE INDEX "index_e2e_reservation" ON "e2e_reservation" (
		"reservation_id"
	);
	CREATE UNIQUE INDEX "index_e2e_index" ON "e2e_index" (
		"reservation",
		"index_number"
	);
	CREATE INDEX "index_e2e_to_seg" ON "e2e_to_seg" (
		"e2e"
	);
	CREATE INDEX "index2_e2e_to_seg" ON "e2e_to_seg" (
		"seg"
	);
	CREATE INDEX "index_e2e_admission_list" ON "e2e_admission_list" (
		"owner_host",
		"valid_until"
	);`
)
