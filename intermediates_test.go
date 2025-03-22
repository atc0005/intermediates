// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package intermediates

import (
	"crypto/x509"
	"testing"
)

// FIXME:
//
// Setup helper function to provide a list of all subjects in
// the returned collection.
//
// t.Logf("%s", Pool().Subjects())

func TestCertsRetrievalCounts(t *testing.T) {
	testFunc := func(t *testing.T, fn func() []*x509.Certificate, expectedCount int) {
		if gotCount := len(fn()); gotCount != expectedCount {
			t.Errorf("intermediates: failed to load all certificates; got %d certificates, wanted %d", gotCount, expectedCount)
		} else {
			t.Logf("intermediates: successfully loaded %d of %d certificates", gotCount, expectedCount)
		}
	}

	testFunc(t, MustGetPublicAllIntermediateCerts, expectedCountPublicAllIntermediateCerts)
	testFunc(t, MustGetMozillaIntermediateCerts, expectedCountMozillaIntermediateCertsReport)
	testFunc(t, MustGetPublicIntermediateCertsRevoked, expectedCountPublicIntermediateCertsRevoked)
}

func TestCertsHashesRetrievalCounts(t *testing.T) {
	testFunc := func(t *testing.T, fn func() []string, expectedCount int) {
		if gotCount := len(fn()); gotCount != expectedCount {
			t.Errorf("intermediates: failed to load all certificate hashes; got %d hashes, wanted %d", gotCount, expectedCount)
		} else {
			t.Logf("intermediates: successfully loaded %d of %d certificate hashes", gotCount, expectedCount)
		}
	}

	testFunc(t, MustGetPublicAllIntermediateCertsHashes, expectedCountPublicAllIntermediateCertsHashes)
	testFunc(t, MustGetMozillaIntermediateCertsHashes, expectedCountMozillaIntermediateCertsReportHashes)
	testFunc(t, MustGetPublicIntermediateCertsRevokedHashes, expectedCountPublicIntermediateCertsRevokedHashes)
}

func TestCertsRetrievalFromGetFuncs(t *testing.T) {
	if certs, err := GetPublicAllIntermediateCerts(); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("intermediates: successfully loaded %d certificates via GetPublicAllIntermediateCerts func.", len(certs))
	}

	if certs, err := GetMozillaIntermediateCerts(); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("intermediates: successfully loaded %d certificates via GetMozillaIntermediateCerts func.", len(certs))
	}

	if certs, err := GetPublicIntermediateCertsRevoked(); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("intermediates: successfully loaded %d certificates via GetPublicIntermediateCertsRevoked func.", len(certs))
	}
}

func TestCertsRetrievalFromMustGetFuncs(t *testing.T) {
	certs := MustGetPublicAllIntermediateCerts()
	t.Logf("intermediates: successfully loaded %d certificates via MustGetPublicAllIntermediateCerts func.", len(certs))

	certs = MustGetMozillaIntermediateCerts()
	t.Logf("intermediates: successfully loaded %d certificates via MustGetMozillaIntermediateCerts func.", len(certs))

	certs = MustGetPublicIntermediateCertsRevoked()
	t.Logf("intermediates: successfully loaded %d certificates via MustGetPublicIntermediateCertsRevoked func.", len(certs))
}

func TestCertsHashesRetrievalFromGetFuncs(t *testing.T) {
	if certs, err := GetPublicAllIntermediateCertsHashes(); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("intermediates: successfully loaded %d certificate hashes via GetPublicAllIntermediateCertsHashes func.", len(certs))
	}

	if certs, err := GetMozillaIntermediateCertsHashes(); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("intermediates: successfully loaded %d certificate hashes via GetMozillaIntermediateCertsHashes func.", len(certs))
	}

	if certs, err := GetPublicIntermediateCertsRevokedHashes(); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("intermediates: successfully loaded %d certificate hashes via GetPublicIntermediateCertsRevokedHashes func.", len(certs))
	}
}

func TestCertsHashesRetrievalFromMustGetFuncs(t *testing.T) {
	certs := MustGetPublicAllIntermediateCertsHashes()
	t.Logf("intermediates: successfully loaded %d certificate hashes via MustGetPublicAllIntermediateCertsHashes func.", len(certs))

	certs = MustGetMozillaIntermediateCertsHashes()
	t.Logf("intermediates: successfully loaded %d certificate hashes via MustGetMozillaIntermediateCertsHashes func.", len(certs))

	certs = MustGetPublicIntermediateCertsRevokedHashes()
	t.Logf("intermediates: successfully loaded %d certificate hashes via MustGetPublicIntermediateCertsRevokedHashes func.", len(certs))
}
