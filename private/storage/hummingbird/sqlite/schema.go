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

// This file contains an SQLite backend for the HummingbirdDB.

package sqlite

const (
	// SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	SchemaVersion = 1
	// Schema is the SQLite database layout.
	Schema = `CREATE TABLE Flyovers(
		RowID INTEGER PRIMARY KEY,
		ia INTEGER NOT NULL,
		ingress INTEGER NOT NULL,
		egress INTEGER NOT NULL,
		resID INTEGER NOT NULL,
		bw INTEGER NOT NULL,
		notBefore INTEGER NOT NULL,
		notAfter INTEGER NOT NULL,
		ak BLOB NOT NULL,
		UNIQUE(ia,resID) ON CONFLICT REPLACE
	);
	`
)
