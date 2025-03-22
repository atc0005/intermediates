// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd
//
// Code in this file inspired by or generated with the help of:
//
// - ChatGPT, OpenAI
// - Google Gemini
// - Claude (Anthropic AI assistant)

package intermediates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	_ "embed"
)

var (

	//go:embed certificates/PublicAllIntermediateCerts.pem
	embeddedPublicAllIntermediateCerts []byte //nolint:gochecknoglobals
	//go:embed certificates/MozillaIntermediateCerts.pem
	embeddedMozillaIntermediateCerts []byte //nolint:gochecknoglobals

	//go:embed certificates/PublicIntermediateCertsRevoked.pem
	embeddedPublicIntermediateCertsRevoked []byte //nolint:gochecknoglobals
)

var (
	//go:embed hashes/PublicAllIntermediateCertsHashes.txt
	embeddedPublicAllIntermediateCertHashes []byte //nolint:gochecknoglobals

	//go:embed hashes/MozillaIntermediateCertsHashes.txt
	embeddedMozillaIntermediateCertHashes []byte //nolint:gochecknoglobals

	//go:embed hashes/PublicIntermediateCertsRevokedHashes.txt
	embeddedPublicIntermediateCertsRevokedHashes []byte //nolint:gochecknoglobals
)

var (
	// ErrNoCertificatesFound indicates that no certificates were found. Since
	// certificates are embedded this is a highly unusual error condition.
	ErrNoCertificatesFound = errors.New("no certificates found")

	// ErrNoCertificateHashesFound indicates that no certificate hashes were
	// found. Since certificate hashes are embedded this is a highly unusual
	// error.
	ErrNoCertificateHashesFound = errors.New("no certificate hashes found")
)

// MustGetPublicAllIntermediateCerts returns an embedded certificates
// collection containing a set of valid intermediate certificates and expired
// intermediate certificates but not revoked intermediate certificates.
//
// These certificates must not be used as trusted roots. Instead, they can be
// used as valid intermediate certificates for completing certificate chains.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func MustGetPublicAllIntermediateCerts() []*x509.Certificate {
	return mustParseCertificates(embeddedPublicAllIntermediateCerts)
}

// MustGetPublicAllIntermediateCertsHashes returns an embedded collection of
// certificate hashes for valid intermediate certificates and expired
// intermediate certificates but not revoked intermediate certificates.
//
// These hashes represent certificates that must not be used as trusted roots.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func MustGetPublicAllIntermediateCertsHashes() []string {
	return mustParseHashes(embeddedPublicAllIntermediateCertHashes)
}

// GetPublicAllIntermediateCerts returns an embedded certificates collection
// containing a set of valid intermediate certificates and expired
// intermediate certificates but not revoked intermediate certificates.
//
// These certificates must not be used as trusted roots. Instead, they can be
// used as valid intermediate certificates for completing certificate chains.
//
// This function returns an error if an issue is encountered parsing the
// embedded intermediates collection. With CI validating the intermediates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func GetPublicAllIntermediateCerts() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedPublicAllIntermediateCerts)
}

// GetPublicAllIntermediateCertsHashes returns an embedded collection of
// certificate hashes for valid intermediate certificates and expired
// intermediate certificates but not revoked intermediate certificates.
//
// These hashes represent certificates that must not be used as trusted roots.
//
// This function returns an error if an issue is encountered parsing the
// embedded intermediates collection. With CI validating the intermediates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func GetPublicAllIntermediateCertsHashes() ([]string, error) {
	return parseHashes(embeddedPublicAllIntermediateCertHashes)
}

// MustGetMozillaIntermediateCerts returns an embedded certificates collection
// containing a set of known WebPKI intermediates chaining to roots in the
// Mozilla Root Program.
//
// These certificates must not be used as trusted roots. Instead, they can be
// used as valid intermediate certificates for completing certificate chains.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func MustGetMozillaIntermediateCerts() []*x509.Certificate {
	return mustParseCertificates(embeddedMozillaIntermediateCerts)
}

// MustGetMozillaIntermediateCertsHashes returns an embedded collection of
// certificate hashes for a set of known WebPKI intermediates chaining to
// roots in the Mozilla Root Program.
//
// These hashes represent certificates that must not be used as trusted roots.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func MustGetMozillaIntermediateCertsHashes() []string {
	return mustParseHashes(embeddedMozillaIntermediateCertHashes)
}

// GetMozillaIntermediateCerts returns an embedded certificates collection
// containing a set of known WebPKI intermediates chaining to roots in the
// Mozilla Root Program.
//
// These certificates must not be used as trusted roots. Instead, they can be
// used as valid intermediate certificates for completing certificate chains.
//
// This function returns an error if an issue is encountered parsing the
// embedded intermediates collection. With CI validating the intermediates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func GetMozillaIntermediateCerts() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedMozillaIntermediateCerts)
}

// GetMozillaIntermediateCertsHashes returns an embedded collection of
// certificate hashes for a set of known WebPKI intermediates chaining to
// roots in the Mozilla Root Program.
//
// These hashes represent certificates that must not be used as trusted roots.
//
// This function returns an error if an issue is encountered parsing the
// embedded intermediates collection. With CI validating the intermediates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func GetMozillaIntermediateCertsHashes() ([]string, error) {
	return parseHashes(embeddedMozillaIntermediateCertHashes)
}

// MustGetPublicIntermediateCertsRevoked returns a certificates collection
// containing revoked intermediate CA certificates which chained to roots in
// the Mozilla Root Program.
//
// These certificates must not be used as trusted roots, nor should they be
// used as valid intermediate certificates for completing certificate chains.
// Instead, this collection is intended to assist diagnostic tools with
// flagging problematic certificate chains.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
//
// NOTE: Due to parsing and decoding issues with the PEM data provided by the
// upstream report this collection is missing just under 1% of the published
// CA certificates. If you need a complete list it is recommended that you
// consume the list of certificate hashes instead.
func MustGetPublicIntermediateCertsRevoked() []*x509.Certificate {
	return mustParseCertificates(embeddedPublicIntermediateCertsRevoked)
}

// MustGetPublicIntermediateCertsRevokedHashes returns an embedded collection
// of certificate hashes for revoked intermediate CA certificates which
// chained to roots in the Mozilla Root Program.
//
// These hashes represent certificates that must not be used as trusted roots.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func MustGetPublicIntermediateCertsRevokedHashes() []string {
	return mustParseHashes(embeddedPublicIntermediateCertsRevokedHashes)
}

// GetPublicIntermediateCertsRevoked returns a certificates collection
// containing revoked intermediate CA certificates which chained to roots in
// the Mozilla Root Program.
//
// These certificates must not be used as trusted roots, nor should they be
// used as valid intermediate certificates for completing certificate chains.
// Instead, this collection is intended to assist diagnostic tools with
// flagging problematic certificate chains.
//
// This function returns an error if an issue is encountered parsing the
// embedded intermediates collection. With CI validating the intermediates
// bundle generated from the upstream Mozilla report it is expected to always
// be in a valid/consistent state. Even so, this function allows the caller to
// guard against any potential issues loading certificates.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
//
// NOTE: Due to parsing and decoding issues with the PEM data provided by the
// upstream report this collection is missing just under 1% of the published
// CA certificates. If you need a complete list it is recommended that you
// consume the list of certificate hashes instead.
func GetPublicIntermediateCertsRevoked() ([]*x509.Certificate, error) {
	return parseCertificates(embeddedPublicIntermediateCertsRevoked)
}

// GetPublicIntermediateCertsRevokedHashes returns an embedded collection of
// certificate hashes for revoked intermediate CA certificates which chained
// to roots in the Mozilla Root Program.
//
// These hashes represent certificates that must not be used as trusted roots.
//
// This function panics if an issue is encountered parsing the embedded
// intermediates collection; because CI validates the intermediates bundle
// generated from the upstream Mozilla report it is expected to always be in a
// valid/consistent state.
//
// This collection is generated from reports provided by Mozilla via
// https://wiki.mozilla.org/CA/Intermediate_Certificates
func GetPublicIntermediateCertsRevokedHashes() ([]string, error) {
	return parseHashes(embeddedPublicIntermediateCertsRevokedHashes)
}

// parseCertificates parses PEM-encoded certificates into x509.Certificate
// values.
func parseCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	pemBlock := &pem.Block{}

	// Create a buffer for the PEM data.
	pemBuffer := bytes.NewBuffer(pemData)

	// Decode each PEM block
	for {
		pemBlock, pemBuffer = decodePEMBlock(pemBuffer)
		if pemBlock == nil {
			break
		}

		// Skip non-certificate blocks
		if pemBlock.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certificates = append(certificates, cert)
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("PEM data invalid: %w", ErrNoCertificatesFound)
	}

	return certificates, nil
}

// mustParseCertificates parses PEM-encoded certificates into x509.Certificate
// values.
func mustParseCertificates(pemData []byte) []*x509.Certificate {
	var certificates []*x509.Certificate

	pemBlock := &pem.Block{}

	// Create a buffer for the PEM data.
	pemBuffer := bytes.NewBuffer(pemData)

	// Decode each PEM block
	for {
		pemBlock, pemBuffer = decodePEMBlock(pemBuffer)
		if pemBlock == nil {
			break
		}

		// Skip non-certificate blocks
		if pemBlock.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			panic(fmt.Errorf("failed to parse certificate: %w", err))
		}

		certificates = append(certificates, cert)
	}

	if len(certificates) == 0 {
		panic(fmt.Errorf("PEM data invalid: %w", ErrNoCertificatesFound))
	}

	return certificates
}

func parseHashes(data []byte) ([]string, error) {
	hashes := strings.Split(string(data), "\n")

	// Remove trailing empty string, if present.
	if len(hashes) > 0 && hashes[len(hashes)-1] == "" {
		hashes = hashes[:len(hashes)-1]
	}

	if len(hashes) == 0 {
		return nil, ErrNoCertificateHashesFound
	}

	return hashes, nil
}

func mustParseHashes(data []byte) []string {
	hashes := strings.Split(string(data), "\n")

	// Remove trailing empty string, if present.
	if len(hashes) > 0 && hashes[len(hashes)-1] == "" {
		hashes = hashes[:len(hashes)-1]
	}

	if len(hashes) == 0 {
		panic(ErrNoCertificateHashesFound)
	}

	return hashes
}

// decodePEMBlock decodes a single PEM block from the buffer. A new buffer
// containing the unprocessed PEM data is returned along with the decoded PEM
// block.
func decodePEMBlock(pemBuffer *bytes.Buffer) (*pem.Block, *bytes.Buffer) {
	if pemBuffer.Len() == 0 {
		return nil, pemBuffer
	}

	block, rest := pem.Decode(pemBuffer.Bytes())
	if block == nil {
		return nil, pemBuffer
	}

	pemBuffer = bytes.NewBuffer(rest)
	return block, pemBuffer
}

// func maxVal(nums ...int) int {
//         if len(nums) == 0 {
//                 return 0
//         }
//
//         maxValue := nums[0]
//         for _, num := range nums[1:] {
//                 if num > maxValue {
//                         maxValue = num
//                 }
//         }
//         return maxValue
// }
