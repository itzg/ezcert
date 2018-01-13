//
// Copyright 2018 Geoff Bourne
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ezcert

import (
	"crypto/x509/pkix"
	"strings"
	"github.com/pkg/errors"
	"github.com/alecthomas/kingpin"
)

// DNValue implements the flag.Value interface
type DNValue pkix.Name

func (n *DNValue) Set(value string) error {
	parts := strings.Split(value, ";")
	for _, part := range parts {
		keyVal := strings.SplitN(part, "=", 2)
		if len(keyVal) != 2 {
			return errors.Errorf("Invalid DN syntax, part=%v was not a key=value", part)
		}

		val := keyVal[1]
		switch strings.ToLower(keyVal[0]) {
		case "c":
			n.Country = []string{val}
		case "st":
			n.Province = []string{val}
		case "l":
			n.Locality = []string{val}
		case "o":
			n.Organization = []string{val}
		case "ou":
			n.OrganizationalUnit = []string{val}
		case "cn":
			n.CommonName = val
		default:
			return errors.Errorf("Unknown name part key: %v", keyVal[0])
		}
	}

	missingParts := make([]string, 0, 6)
	if n.Country == nil {
		missingParts = append(missingParts, "Country(C)")
	}
	if n.Province == nil {
		missingParts = append(missingParts, "Province/State(ST)")
	}
	if n.Locality == nil {
		missingParts = append(missingParts, "Locality(L)")
	}
	if n.Organization == nil {
		missingParts = append(missingParts, "Organization(O)")
	}
	if n.OrganizationalUnit == nil {
		missingParts = append(missingParts, "OrganizationalUnit(OU)")
	}

	if len(missingParts) > 0 {
		return errors.Errorf("DN is missing %s", strings.Join(missingParts, ", "))
	}

	return nil
}

func (n *DNValue) String() string {
	return ""
}

// DN is a convenience function to wrap a kingping Arg declaration
func DN(s kingpin.Settings) (target *pkix.Name) {
	target = &pkix.Name{}
	s.SetValue((*DNValue)(target))
	return
}