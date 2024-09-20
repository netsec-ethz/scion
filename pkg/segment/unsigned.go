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

package segment

import (
	"bytes"
	"encoding/hex"

	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	"github.com/scionproto/scion/pkg/segment/extensions/epic"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

type UnsignedExtensions struct {
	// EpicDetached contains the detachable epic authenticators. It is nil
	// if it was detached (or never added).
	EpicDetached *epic.Detached
	// FabridDetached contains the detachable fabrid maps. It is nil if it was detached
	FabridDetached *fabrid.Detached
}

func UnsignedExtensionsFromPB(ue *cppb.PathSegmentUnsignedExtensions) UnsignedExtensions {
	if ue == nil {
		return UnsignedExtensions{}
	}
	return UnsignedExtensions{
		EpicDetached:   epic.DetachedFromPB(ue.Epic),
		FabridDetached: fabrid.DetachedFromPB(ue.Fabrid),
	}
}

func UnsignedExtensionsToPB(ue UnsignedExtensions) *cppb.PathSegmentUnsignedExtensions {
	var e *experimental.EPICDetachedExtension
	var f *experimental.FABRIDDetachedExtension

	if ue.EpicDetached == nil {
		e = nil
	} else {
		e = epic.DetachedToPB(ue.EpicDetached)
	}

	if ue.FabridDetached == nil {
		f = nil
	} else {
		f = fabrid.DetachedToPB(ue.FabridDetached)
	}

	return &cppb.PathSegmentUnsignedExtensions{
		Epic:   e,
		Fabrid: f,
	}
}

// checkUnsignedExtensions checks whether the unsigned extensions are consistent with the
// signed hash. Furthermore, an unsigned extension is not valid if it is present in the
// ASEntry, but the corresponding hash is not.
func checkUnsignedExtensions(ue *UnsignedExtensions, e *Extensions) error {
	if ue == nil || e == nil {
		return serrors.New("invalid input to checkUnsignedExtensions")
	}

	// If unsigned extension is present but hash is not, return error
	// EPIC:
	epicDetached := (ue.EpicDetached != nil)
	epicDigest := (e.Digests != nil && len(e.Digests.Epic.Digest) != 0)
	if epicDetached && !epicDigest {
		return serrors.New("epic authenticators present, but hash is not")
	}

	// Check consistency (digest extension contains correct hash)
	// EPIC:
	if epicDetached && epicDigest {
		input, err := ue.EpicDetached.DigestInput()
		if err != nil {
			return err
		}
		if err := e.Digests.Epic.Validate(input); err != nil {
			return err
		}
	}

	if ue.FabridDetached != nil {
		hasSupportedIndices := len(ue.FabridDetached.SupportedIndicesMap) > 0
		hasIndexIdentifiers := len(ue.FabridDetached.IndexIdentiferMap) > 0
		fabridDigest := e.Digests != nil && len(e.Digests.Fabrid.Digest) != 0
		if hasSupportedIndices && !hasIndexIdentifiers {
			// An AS may announce index->identifiers that are not used in the supported indices map.
			//However, announcing supported policy indices without specifying the identifiers is
			//invalid.
			return serrors.New("fabrid maps are malformed")
		}

		if fabridDigest {
			if digest := ue.FabridDetached.Hash(); !bytes.Equal(e.Digests.Fabrid.Digest, digest) {
				return serrors.New("fabrid digest validation failed",
					"calculated", hex.EncodeToString(e.Digests.Fabrid.Digest),
					"stored", hex.EncodeToString(digest))
			}
		} else {
			return serrors.New("fabrid maps present, but hash is not")
		}
	}
	return nil
}
