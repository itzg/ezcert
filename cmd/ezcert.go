//
// Copyright 2018 Rackspace
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

package main

import (
	"github.com/alecthomas/kingpin"
	"github.com/itzg/ezcert"
	"fmt"
	"os"
)

var Version string = "DEV"

var (
	createCa        = kingpin.Command("ca", "Create a CA certificate")
	createCaSubject = ezcert.DN(createCa.Flag("subject", "A distinguished name (DN) of the CA, " +
		"such as CN=widgets.com,C=US,L=Dallas,ST=Texas,O=Internet Widgets,OU=WWW").
		Required())
	createCaExpires = createCa.Flag("expires", "Specifies the number of days to make a certificate valid for").
		Default("30").Int()
	createCaKeyBits = createCa.Flag("key-bits", "Bit length of the private key to generate").
		Default("2048").Int()
	createCaOut = createCa.Flag("out", "Existing directory the CA files will be written").Default("certs").
		ExistingDir()
)


func main() {
	kingpin.Version(Version)

	switch kingpin.Parse() {
	case createCa.FullCommand():
		fmt.Println("Running ca command")
		err := ezcert.CreateCaCertAndKey(*createCaOut, *createCaSubject, *createCaExpires, *createCaKeyBits)
		if err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(1)
		}
	}
}
