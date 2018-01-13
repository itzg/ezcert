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

package main

import (
	"github.com/alecthomas/kingpin"
	"github.com/itzg/ezcert"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

var version string = "DEV"

var (
	subject = ezcert.DN(kingpin.Flag("subject", "A distinguished name (DN) of the certificate's subject, "+
		"such as CN=widgets.com;C=US;L=Dallas;ST=Texas;O=Internet Widgets;OU=WWW").
		Required())
	expires = kingpin.Flag("expires", "Specifies the number of days to make a certificate valid for").
		Default("30").Int()
	keyBits = kingpin.Flag("key-bits", "Bit length of the private key to generate").
		Default("2048").Int()
	out = kingpin.Flag("out", "Existing directory where the certificate and key files will be written").
		Default("certs").
		ExistingDir()
	logColor = kingpin.Flag("log-color", "Force color log format").Action(func(context *kingpin.ParseContext) error {
		log.SetFormatter(&log.TextFormatter{ForceColors: true, TimestampFormat: time.RFC822, FullTimestamp: true})
		return nil
	}).Bool()

	createCa = kingpin.Command("ca", "Create a CA certificate")

	createClient       = kingpin.Command("client", "Create a client certificate from a CA certificate")
	createClientCaCert = createClient.Flag("ca-cert", "An existing CA certificate").
				Required().ExistingFile()
	createClientUserPrefix = createClient.Flag("prefix", "A prefix to use for the generated files").String()

	createServer       = kingpin.Command("server", "Create a server certificate from a CA certificate")
	createServerCaCert = createServer.Flag("ca-cert", "An existing CA certificate").
				Required().ExistingFile()
	createServerUserPrefix = createServer.Flag("prefix", "A prefix to use for the generated files").String()
	createServerDnsNames   = createServer.Flag("dns", "A DNS based SAN for this server. Can be repeated.").Strings()
)

func main() {
	kingpin.Version(version)

	switch kingpin.Parse() {
	case createCa.FullCommand():
		log.Info("Generating CA certificate")
		err := ezcert.CreateCaCertAndKey(*out, *subject, *expires, *keyBits)
		if err != nil {
			log.WithError(err).Error("Failed to generate CA certificate")
			os.Exit(1)
		}

	case createClient.FullCommand():
		log.WithField("subject", *subject).Info("Generating client certificate")
		err := ezcert.CreateClientCertAndKey(*out, *subject, *expires, *keyBits, *createClientCaCert, *createClientUserPrefix)
		if err != nil {
			log.WithError(err).Error("Failed to generate client certificate")
			os.Exit(1)
		}

	case createServer.FullCommand():
		log.
			WithField("subject", *subject).
			WithField("SANs", *createServerDnsNames).
			Info("Generating server certificate")
		err := ezcert.CreateServerCertAndKey(*out, *subject, *expires, *keyBits, *createServerCaCert, *createServerUserPrefix, *createServerDnsNames)
		if err != nil {
			log.WithError(err).Error("Failed to generate Server certificate")
			os.Exit(1)
		}
	}
}
