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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	FileTypeCert     = "cert"
	FileTypeBundle   = "bundle"
	FileTypeRsaKey   = "rsa-key"
	FileTypePkcs8Key = "pkcs8-key"

	PemBlockTypeCertificate     = "CERTIFICATE"
	PemBlockTypeRsaPrivateKey   = "RSA PRIVATE KEY"
	PemBlockTypePkcs8PrivateKey = "PRIVATE KEY"

	DataFilename = "ezcert-data.json"
)

type Pkcs8Key struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type Data struct {
	SerialNumber int64
}

func AllocateSerialNumber() (*big.Int, error) {
	var data Data

	configDirs := configdir.New("me.itzg", "ezcert")
	configDirs.LocalPath, _ = filepath.Abs(".")

	folder := configDirs.QueryFolderContainsFile(DataFilename)
	if folder != nil {
		bytes, err := folder.ReadFile(DataFilename)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to read %s", DataFilename)
		}
		err = json.Unmarshal(bytes, &data)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to unmarshal ezcert data")
		}
	}

	data.SerialNumber++

	bytes, err := json.Marshal(&data)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to marshal ezcert data")
	}
	if folder == nil {
		folder = configDirs.QueryFolders(configdir.Global)[0]
	}

	err = folder.WriteFile(DataFilename, bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to write %s", DataFilename)
	}

	return big.NewInt(data.SerialNumber), nil
}

func CreateCaCertAndKey(out string, subject pkix.Name, expires int, keyBits int) error {

	privateKey, templateCert, err := newKeyAndTemplate(subject, expires, keyBits)
	if err != nil {
		return err
	}
	templateCert.IsCA = true
	templateCert.BasicConstraintsValid = true
	templateCert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	certDer, err := x509.CreateCertificate(rand.Reader, templateCert, templateCert, privateKey.Public(), privateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to create self-signed CA certificate")
	}

	return WriteCertKeyFiles(out, "ca", "RSA", certDer, privateKey)
}

func newKeyAndTemplate(subject pkix.Name, expires int, keyBits int) (*rsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to generate RSA private key")
	}

	subjectKeyId, err := generateSubjectKeyId(privateKey.Public())
	if err != nil {
		return nil, nil, errors.Wrap(err, "Unable to generate subject key identifier")
	}

	var templateCert x509.Certificate
	templateCert.Subject = subject
	templateCert.SerialNumber, err = AllocateSerialNumber()
	if err != nil {
		log.WithError(err).Warn("Failed to allocate serial number, using fixed value")
		templateCert.SerialNumber = big.NewInt(1)
	}
	templateCert.SubjectKeyId = subjectKeyId
	templateCert.NotBefore = time.Now()
	templateCert.NotAfter = time.Now().AddDate(0, 0, expires)

	return privateKey, &templateCert, nil
}

func CreateClientCertAndKey(out string, subject pkix.Name, expires int, keyBits int, caCertPath string, userPrefix string) error {

	signerCert, err := readCertFromPemFile(caCertPath)
	if err != nil {
		return err
	}

	privateKey, templateCert, err := newKeyAndTemplate(subject, expires, keyBits)
	if err != nil {
		return err
	}

	templateCert.IsCA = false
	templateCert.BasicConstraintsValid = true
	templateCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	certDer, err := x509.CreateCertificate(rand.Reader, templateCert, signerCert, privateKey.Public(), privateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to create self-signed CA certificate")
	}

	var fullPrefix string
	if userPrefix != "" {
		fullPrefix = userPrefix + "-client"
	} else {
		fullPrefix = "client"
	}
	return WriteCertKeyFiles(out, fullPrefix, "RSA", certDer, privateKey)
}

func readCertFromPemFile(certPath string) (*x509.Certificate, error) {
	caCertBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to read %s", certPath)
	}

	remainder := caCertBytes
	for len(remainder) > 0 {
		var caCertBlock *pem.Block
		caCertBlock, remainder = pem.Decode(caCertBytes)
		if caCertBlock != nil && caCertBlock.Type == PemBlockTypeCertificate {
			certificate, err := x509.ParseCertificate(caCertBlock.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, "Unable to parse certificate from %s", certPath)
			}
			return certificate, nil
		}
	}

	return nil, errors.Errorf("The file %s did not contain a certificate block", certPath)
}

func WriteCertKeyFiles(out string, prefix string, keyAlgorithm string, certDer []byte, privateKey *rsa.PrivateKey) error {

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyPkcs8Der, err := MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return errors.Wrap(err, "Unable to marshal private key into PKCS8")
	}

	// Open all the files here since the cert and RSA key are written to their own and the bundle file

	certPath := filepath.Join(out, fmt.Sprintf("%s-%s.pem", prefix, FileTypeCert))
	certFile, err := os.Create(certPath)
	if err != nil {
		return errors.Wrap(err, "Unable to create cert pem file")
	}
	defer certFile.Close()

	bundlePath := filepath.Join(out, fmt.Sprintf("%s-%s.pem", prefix, FileTypeBundle))
	bundleFile, err := os.Create(bundlePath)
	if err != nil {
		return errors.Wrap(err, "Unable to create bundle pem file")
	}
	defer bundleFile.Close()

	rsaKeyPath := filepath.Join(out, fmt.Sprintf("%s-%s.pem", prefix, FileTypeRsaKey))
	rsaKeyFile, err := os.Create(rsaKeyPath)
	if err != nil {
		return errors.Wrap(err, "Unable to create rsaKey pem file")
	}
	defer rsaKeyFile.Close()

	pkcs8KeyPath := filepath.Join(out, fmt.Sprintf("%s-%s.pem", prefix, FileTypePkcs8Key))
	pkcs8KeyFile, err := os.Create(pkcs8KeyPath)
	if err != nil {
		return errors.Wrap(err, "Unable to create pkcs8Key pem file")
	}
	defer pkcs8KeyFile.Close()

	// PEM encode and write to those files

	err = EncodePem(certFile, PemBlockTypeCertificate, certDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write certificate file")
	}
	log.Infof("Wrote %s", certPath)

	err = EncodePem(rsaKeyFile, PemBlockTypeRsaPrivateKey, privateKeyDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write private RSA key file")
	}
	log.Infof("Wrote %s", rsaKeyPath)

	err = EncodePem(bundleFile, PemBlockTypeCertificate, certDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write bundle file")
	}
	err = EncodePem(bundleFile, PemBlockTypeRsaPrivateKey, privateKeyDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write bundle file")
	}
	log.Infof("Wrote %s", bundlePath)

	err = EncodePem(pkcs8KeyFile, PemBlockTypePkcs8PrivateKey, privateKeyPkcs8Der)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write private PKCS8/RSA key file")
	}
	log.Infof("Wrote %s", pkcs8KeyPath)

	return nil
}

func EncodePem(writer io.Writer, blockType string, der []byte) error {
	certPemBlock := pem.Block{
		Type:  blockType,
		Bytes: der,
	}

	err := pem.Encode(writer, &certPemBlock)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write DER content")
	}

	return nil

}

func MarshalPKCS8PrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	// Thanks to https://stackoverflow.com/a/40510456/121324

	pkcsKey := Pkcs8Key{
		PrivateKeyAlgorithm: make([]asn1.ObjectIdentifier, 1),
		PrivateKey:          x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// pkcs-1.rsaEncryption
	// http://oid-info.com/get/1.2.840.113549.1.1.1
	pkcsKey.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	return asn1.Marshal(pkcsKey)
}

func generateSubjectKeyId(publicKey crypto.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	keySha := sha1.New().Sum(bytes)
	// The leading and the trailing bytes of the SHA1 of the public key didn't seem to vary
	// so taking a slice from an inner part resulted in a derived but variable identifier
	return keySha[34:54], nil
}
