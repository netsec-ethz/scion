// Copyright 2018 ETH Zurich
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

package main

import "time"

const (
	DefaultDRKeyTimeout = 5 * time.Second
	// TODO(ben): move to config
	DRKeyEpochLength = 24 * time.Hour
)

// TODO:
// - derive and store secret value of current epoch
// - before epoch expires or key for next epoch is requested, get new secret value
// - fetch first order keys from other ASes if they are not available?
// - keep track of frequently connected ASes?
