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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"os"
	"path/filepath"
	"time"
	"encoding/asn1"
	"math/big"
	"crypto/sha1"
	"crypto"
)

const (
	FileTypeCert   = "cert"
	FileTypeBundle = "bundle"
	FileTypeRsaKey = "rsa-key"
	FileTypePkcs8Key = "pkcs8-key"

	PemBlockTypeCertificate     = "CERTIFICATE"
	PemBlockTypeRsaPrivateKey   = "RSA PRIVATE KEY"
	PemBlockTypePkcs8PrivateKey = "PRIVATE KEY"
)

type Pkcs8Key struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

func CreateCaCertAndKey(out string, subject pkix.Name, expires int, keyBits int) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return errors.Wrap(err, "Failed to generate RSA private key")
	}

	subjectKeyId, err := generateSubjectKeyId(privateKey.Public())
	if err != nil {
		return errors.Wrap(err, "Unable to generate subject key identifier")
	}

	var templateCert x509.Certificate
	templateCert.Subject = subject
	templateCert.SerialNumber = big.NewInt(1)
	templateCert.IsCA = true
	templateCert.SubjectKeyId = subjectKeyId
	templateCert.BasicConstraintsValid = true
	templateCert.NotBefore = time.Now()
	templateCert.NotAfter = time.Now().AddDate(0, 0, expires)
	templateCert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	certDer, err := x509.CreateCertificate(rand.Reader, &templateCert, &templateCert, privateKey.Public(), privateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to create self-signed CA certificate")
	}

	return WriteCertKeyFiles(out, "ca", "RSA", certDer, privateKey)
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
	err = EncodePem(bundleFile, PemBlockTypeCertificate, certDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write bundle file")
	}

	err = EncodePem(rsaKeyFile, PemBlockTypeRsaPrivateKey, privateKeyDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write private RSA key file")
	}
	err = EncodePem(bundleFile, PemBlockTypeRsaPrivateKey, privateKeyDer)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write bundle file")
	}

	err = EncodePem(pkcs8KeyFile, PemBlockTypePkcs8PrivateKey, privateKeyPkcs8Der)
	if err != nil {
		return errors.Wrap(err, "Unable to encode/write private PKCS8/RSA key file")
	}

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
		PrivateKey: x509.MarshalPKCS1PrivateKey(privateKey),
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