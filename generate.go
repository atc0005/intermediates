// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build generate
// +build generate

// Tool used to generate intermediate certificate hashes and certificates
// chaining to roots in the Mozilla Root Program.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

//go:generate go run generate.go

// CAs are required to provide the data for all of their publicly disclosed
// and audited intermediate certificates which chain up to root certificates
// in Mozilla's program. They do this using the CCADB.
//
// The following URLs are for reports that are generated once per day.
//
// See https://wiki.mozilla.org/CA/Intermediate_Certificates for further
// information.
const (
	// urlPublicAllIntermediateCertsReport is the URL to a report of the valid
	// intermediate certificates and expired intermediate certificates but not
	// revoked intermediate certificates (CSV with PEM of raw certificate
	// data).
	urlPublicAllIntermediateCertsReport = "https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV"

	// urlMozillaIntermediateCertsReport is the URL to a report of the
	// non-revoked, non-expired Intermediate CA Certificates chaining up to
	// roots in Mozilla's program with the Websites trust bit set (CSV with
	// PEM of raw certificate data).
	urlMozillaIntermediateCertsReport = "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport"

	// urlPublicIntermediateCertsRevoked is the URL to a report of the revoked
	// intermediate CA certificates (CSV with PEM of raw certificate data).
	urlPublicIntermediateCertsRevoked = "https://ccadb.my.salesforce-sites.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV"
)

// Output files for the original reports.
const (
	csvOutputPublicAllIntermediateCerts     = "PublicAllIntermediateCertsWithPEMReport.csv"
	csvOutputMozillaIntermediateCertsReport = "MozillaIntermediateCerts.csv"
	csvOutputPublicIntermediateCertsRevoked = "PublicIntermediateCertsRevokedWithPEMReport.csv"
)

// Output files for the generated intermediate bundles.
const (
	pemOutputPublicAllIntermediateCerts     = "PublicAllIntermediateCerts.pem"
	pemOutputMozillaIntermediateCertsReport = "MozillaIntermediateCerts.pem"
	pemOutputPublicIntermediateCertsRevoked = "PublicIntermediateCertsRevoked.pem"
)

// Output files for the intermediate hashes.
const (
	hashesOutputPublicAllIntermediateCerts     = "PublicAllIntermediateCertsHashes.txt"
	hashesOutputMozillaIntermediateCertsReport = "MozillaIntermediateCertsHashes.txt"
	hashesOutputPublicIntermediateCertsRevoked = "PublicIntermediateCertsRevokedHashes.txt"
)

const counterOutputFile = "count.go"

type intermediate struct {
	Subject string
	Issuer  string
	PEM     string
	Hash    [sha256.Size]byte
}

type intermediateCSVColumns struct {
	Subject            int
	Issuer             int
	Hash               int
	PEM                int
	Comments           int
	CommentsHeaderName string
	HashHeaderName     string
	PEMHeaderName      string
}

type parsingOptions struct {
	IgnoreDecodeErrors bool
	IgnoreParseErrors  bool
}

type writtenCounterLog struct {
	PublicAllIntermediateCerts           int
	PublicAllIntermediateCertsHashes     int
	MozillaIntermediateCertsReport       int
	MozillaIntermediateCertsReportHashes int
	PublicIntermediateCertsRevoked       int
	PublicIntermediateCertsRevokedHashes int
}

func main() {
	// Emulate returning exit code from main function by "queuing up" a
	// default exit code that matches expectations, but allow explicitly
	// setting the exit code in such a way that is compatible with using
	// deferred function calls throughout the application.
	var appExitCode int
	defer func(code *int) {
		var exitCode int
		if code != nil {
			exitCode = *code
		}
		os.Exit(exitCode)
	}(&appExitCode)

	log.Print("Downloading CSV reports")

	if err := downloadCSVFile(urlPublicAllIntermediateCertsReport, csvOutputPublicAllIntermediateCerts); err != nil {
		log.Printf("Failed to download CSV file %s: %v", csvOutputPublicAllIntermediateCerts, err)

		appExitCode = 1
		return
	}

	if err := downloadCSVFile(urlMozillaIntermediateCertsReport, csvOutputMozillaIntermediateCertsReport); err != nil {
		log.Printf("Failed to download CSV file %s: %v", csvOutputMozillaIntermediateCertsReport, err)

		appExitCode = 1
		return
	}

	if err := downloadCSVFile(urlPublicIntermediateCertsRevoked, csvOutputPublicIntermediateCertsRevoked); err != nil {
		log.Printf("Failed to download CSV file %s: %v", csvOutputPublicIntermediateCertsRevoked, err)

		appExitCode = 1
		return
	}

	var outputLog writtenCounterLog

	if err := generateAllIntermediatesFiles(&outputLog); err != nil {
		log.Print(err)

		appExitCode = 1
		return
	}

	if err := generateMozillaIntermediatesFiles(&outputLog); err != nil {
		log.Print(err)

		appExitCode = 1
		return
	}

	if err := generateRevokedIntermediatesFiles(&outputLog); err != nil {
		log.Print(err)

		appExitCode = 1
		return
	}

	log.Printf("Generating expected counts record file %q for next CI tests validation", counterOutputFile)

	if err := writeCounterLog(counterOutputFile, outputLog); err != nil {
		log.Printf(
			"Failed to generate output counter file %s: %v",
			counterOutputFile,
			err,
		)

		appExitCode = 1
		return
	}

	log.Printf("Wrote %d intermediates to %q", outputLog.PublicAllIntermediateCerts, pemOutputPublicAllIntermediateCerts)
	log.Printf("Wrote %d hashes to %q", outputLog.PublicAllIntermediateCertsHashes, hashesOutputPublicAllIntermediateCerts)

	log.Printf("Wrote %d intermediates to %q", outputLog.MozillaIntermediateCertsReport, pemOutputMozillaIntermediateCertsReport)
	log.Printf("Wrote %d hashes to %q", outputLog.MozillaIntermediateCertsReportHashes, hashesOutputMozillaIntermediateCertsReport)

	log.Printf("Wrote %d intermediates to %q", outputLog.PublicIntermediateCertsRevoked, pemOutputPublicIntermediateCertsRevoked)
	log.Printf("Wrote %d hashes to %q", outputLog.PublicIntermediateCertsRevokedHashes, hashesOutputPublicIntermediateCertsRevoked)
}

func downloadCSVFile(url string, outputFilename string) error {
	c := &http.Client{Timeout: 1 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Print(err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"GET got %d: %v", resp.StatusCode, resp.Status,
		)
	}

	csvFile, err := os.Create(filepath.Clean(outputFilename))
	if err != nil {
		return err
	}
	defer func() {
		if err := csvFile.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputFilename,
					err,
				)
			}
		}
	}()

	_, err = io.Copy(csvFile, resp.Body)
	if err != nil {
		return err
	}

	return csvFile.Close()
}

// generatePEMFile receives an input CSV file and generates an output PEM file
// using the given intermediateCSVColumns value to locate required input
// columns.
//
// NOTE: The inputCSVColumn value expects zero-based numbers, so to specify
// column 5 you would provide the number 4.
func generatePEMFile(inputCSVFile string, outputPEMFile string, csvColumns intermediateCSVColumns, options parsingOptions) (int, error) {
	var intermediates []intermediate
	seen := make(map[[sha256.Size]byte]bool)

	csvFile, err := os.Open(filepath.Clean(inputCSVFile))
	if err != nil {
		return 0, err
	}

	r := csv.NewReader(csvFile)
	header, err := r.Read()
	if err != nil {
		return 0, err
	}

	if header[csvColumns.PEM] != csvColumns.PEMHeaderName {
		return 0, fmt.Errorf(
			"unexpected input file format: CSV file %s column %d (zero-based) does not contain %s",
			inputCSVFile,
			csvColumns.PEM,
			csvColumns.PEMHeaderName,
		)
	}

	// Not all reports have a Comments field, but where we know of one we
	// assert that it is present.
	if csvColumns.CommentsHeaderName != "" {
		if header[csvColumns.Comments] != csvColumns.CommentsHeaderName {
			return 0, fmt.Errorf(
				"unexpected input file format: CSV file %s column %d (zero-based) does not contain %s",
				inputCSVFile,
				csvColumns.Comments,
				csvColumns.CommentsHeaderName,
			)
		}
	}

	var lineCounter int
	var skipErrCounter int
	for {
		lineCounter++

		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		// Trim any single quotes surrounding PEM data (as observed in the
		// revoked certs input file).
		record[csvColumns.PEM] = strings.Trim(record[csvColumns.PEM], "'")

		b, _ := pem.Decode([]byte(record[csvColumns.PEM]))
		if b == nil {
			// FIXME: Temporary workaround for:
			//
			// PEM too large to save directly in CCADB.\nPEM is here: https://crt.sh/?d=91478107
			//
			// We could hotfix this by retrieving the cert and inserting it into
			// this position of the collection.
			if strings.Contains(record[csvColumns.Comments], "too large") {
				log.Printf("Skipping entry %d for %q due to 'too large' comment in report", lineCounter, record[csvColumns.Subject])
				skipErrCounter++
				continue
			}

			if options.IgnoreDecodeErrors {
				log.Printf("Decode error for entry %d for %q; ignoring this error type as requested", lineCounter, record[csvColumns.Subject])
				skipErrCounter++
				continue
			}

			return 0, fmt.Errorf("record %d is not valid PEM: %#v", lineCounter, record)
		}

		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			if strings.Contains(err.Error(), "x509: invalid key usage") {
				if strings.Contains(record[csvColumns.Comments], "malformed") {
					log.Printf("Skipping entry %d for %s due to 'malformed' comment in report", lineCounter, record[csvColumns.Subject])
					skipErrCounter++
					continue
				}
			}

			// if strings.Contains(err.Error(), "failed to parse dnsName constraint") {
			// 	log.Printf("Parsing error occurred for entry %d: %v", lineCounter, err)
			// 	log.Printf("Skipping record %d due to presumed formatting issue with cert", lineCounter)
			// 	skipErrCounter++
			// 	continue
			// }

			if options.IgnoreParseErrors {
				log.Printf("Parse error for entry %d for %q; ignoring this error type as requested", lineCounter, record[csvColumns.Subject])
				skipErrCounter++
				continue
			}

			log.Printf("%#v", record)

			return 0, fmt.Errorf(
				"invalid certificate for entry %d for %s: %w",
				lineCounter,
				record[csvColumns.Subject],
				err,
			)
		}
		hash := sha256.Sum256(b.Bytes)
		if seen[hash] {
			log.Printf("Duplicate record: %v", record[csvColumns.Subject])
			continue
		}
		seen[hash] = true

		intermediates = append(intermediates, intermediate{
			Subject: record[csvColumns.Subject],
			Issuer:  record[csvColumns.Issuer],
			PEM:     record[csvColumns.PEM],
			Hash:    hash,
		})
	}

	sort.Slice(intermediates, func(i, j int) bool {
		if intermediates[i].Issuer != intermediates[j].Issuer {
			return intermediates[i].Issuer < intermediates[j].Issuer
		}
		if intermediates[i].Subject != intermediates[j].Subject {
			return intermediates[i].Subject < intermediates[j].Subject
		}
		return bytes.Compare(intermediates[i].Hash[:], intermediates[j].Hash[:]) < 0
	})

	text, err := os.Create(filepath.Clean(outputPEMFile))
	if err != nil {
		return 0, err
	}

	defer func() {
		if err := text.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputPEMFile,
					err,
				)
			}
		}
	}()

	for _, i := range intermediates {
		_, err := io.WriteString(text, "# Issuer: "+i.Issuer+"\n")
		if err != nil {
			return 0, err
		}

		_, err = io.WriteString(text, "# Subject: "+i.Subject+"\n")
		if err != nil {
			return 0, err
		}

		_, err = io.WriteString(text, i.PEM)
		if err != nil {
			return 0, err
		}

		_, err = io.WriteString(text, "\n")
		if err != nil {
			return 0, err
		}
	}

	if err := text.Close(); err != nil {
		return 0, err
	}

	if skipErrCounter != 0 {
		log.Printf("NOTE: Ignored %d parse/decode errors for input file %q", skipErrCounter, inputCSVFile)
	}

	return len(intermediates), nil
}

func generateAllIntermediatesFiles(counterLog *writtenCounterLog) error {
	log.Printf("Generating PEM file %q", pemOutputPublicAllIntermediateCerts)

	columns := intermediateCSVColumns{
		Subject:            5,                     // Column F
		Issuer:             3,                     // Column D
		PEM:                25,                    // Column Z
		PEMHeaderName:      "PEM Info",            // Column Z
		Hash:               8,                     // Column I
		HashHeaderName:     "SHA-256 Fingerprint", // Column I
		Comments:           24,                    // Column Y
		CommentsHeaderName: "Comments",            // Column Y
	}

	pemWritten, err := generatePEMFile(
		csvOutputPublicAllIntermediateCerts,
		pemOutputPublicAllIntermediateCerts,
		columns,
		parsingOptions{
			IgnoreDecodeErrors: false,
			IgnoreParseErrors:  false,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate PEM file %s from CSV file %s: %v",
			pemOutputPublicAllIntermediateCerts,
			csvOutputPublicAllIntermediateCerts,
			err,
		)
	}

	counterLog.PublicAllIntermediateCerts = pemWritten

	log.Printf("Generating Hashes file %q", hashesOutputPublicAllIntermediateCerts)

	hashesWritten, err := generateHashFile(
		csvOutputPublicAllIntermediateCerts,
		hashesOutputPublicAllIntermediateCerts,
		columns,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate Hashes file %s from CSV file %s: %v",
			hashesOutputPublicAllIntermediateCerts,
			csvOutputPublicAllIntermediateCerts,
			err,
		)
	}

	counterLog.PublicAllIntermediateCertsHashes = hashesWritten

	return nil
}

func generateMozillaIntermediatesFiles(counterLog *writtenCounterLog) error {
	log.Printf("Generating PEM file %q", pemOutputMozillaIntermediateCertsReport)

	columns := intermediateCSVColumns{
		Subject:        0,        // Column A
		Issuer:         1,        // Column B
		PEM:            4,        // Column E
		PEMHeaderName:  "PEM",    // Column E
		Hash:           2,        // Column C
		HashHeaderName: "SHA256", // Column C
		// No Comments column in this report as of 2025-03-21.
	}

	pemWritten, err := generatePEMFile(
		csvOutputMozillaIntermediateCertsReport,
		pemOutputMozillaIntermediateCertsReport,
		columns,
		parsingOptions{
			IgnoreDecodeErrors: false,
			IgnoreParseErrors:  false,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate PEM file %s from CSV file %s: %v",
			pemOutputMozillaIntermediateCertsReport,
			csvOutputMozillaIntermediateCertsReport,
			err,
		)
	}

	counterLog.MozillaIntermediateCertsReport = pemWritten

	log.Printf("Generating Hashes file %q", hashesOutputMozillaIntermediateCertsReport)

	hashesWritten, err := generateHashFile(
		csvOutputMozillaIntermediateCertsReport,
		hashesOutputMozillaIntermediateCertsReport,
		columns,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate Hashes file %s from CSV file %s: %v",
			hashesOutputMozillaIntermediateCertsReport,
			csvOutputMozillaIntermediateCertsReport,
			err,
		)
	}

	counterLog.MozillaIntermediateCertsReportHashes = hashesWritten

	return nil
}

func generateRevokedIntermediatesFiles(counterLog *writtenCounterLog) error {
	log.Printf("Generating PEM file %q", pemOutputPublicIntermediateCertsRevoked)
	log.Print("NOTE: There are known issues with decoding/parsing PEM data for some of the entries in this report. We ignore those errors only for this report.")

	columns := intermediateCSVColumns{
		Subject:            9,                     // column J
		Issuer:             7,                     // column H
		PEM:                20,                    // Column U
		PEMHeaderName:      "PEM Info",            // Column U
		Hash:               11,                    // Column L
		HashHeaderName:     "SHA-256 Fingerprint", // Column L
		Comments:           19,                    // Column T
		CommentsHeaderName: "Comments",            // Column T
	}

	pemWritten, err := generatePEMFile(
		csvOutputPublicIntermediateCertsRevoked,
		pemOutputPublicIntermediateCertsRevoked,
		columns,
		parsingOptions{
			// Best effort decoding and parsing due to known issues with input
			// data.
			IgnoreDecodeErrors: true,
			IgnoreParseErrors:  true,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate PEM file %s from CSV file %s: %v",
			csvOutputPublicIntermediateCertsRevoked,
			csvOutputPublicIntermediateCertsRevoked,
			err,
		)
	}

	counterLog.PublicIntermediateCertsRevoked = pemWritten

	log.Printf("Generating Hashes file %q", hashesOutputPublicIntermediateCertsRevoked)

	hashesWritten, err := generateHashFile(
		csvOutputPublicIntermediateCertsRevoked,
		hashesOutputPublicIntermediateCertsRevoked,
		columns,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to generate Hashes file %s from CSV file %s: %v",
			hashesOutputPublicIntermediateCertsRevoked,
			csvOutputPublicIntermediateCertsRevoked,
			err,
		)
	}

	counterLog.PublicIntermediateCertsRevokedHashes = hashesWritten

	return nil
}

func generateHashFile(inputCSVFile string, outputTXTFile string, csvColumns intermediateCSVColumns) (int, error) {
	csvFile, err := os.Open(filepath.Clean(inputCSVFile))
	if err != nil {
		return 0, err
	}

	r := csv.NewReader(csvFile)
	header, err := r.Read()
	if err != nil {
		return 0, err
	}

	if header[csvColumns.Hash] != csvColumns.HashHeaderName {
		return 0, fmt.Errorf(
			"unexpected input file format: CSV file %s column %d (zero-based) does not contain %s",
			inputCSVFile,
			csvColumns.Hash,
			csvColumns.HashHeaderName,
		)
	}

	var hashes []string

	seen := make(map[string]bool)

	var lineCounter int

	for {
		lineCounter++

		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		record[csvColumns.Hash] = strings.Trim(record[csvColumns.Hash], "'")
		record[csvColumns.Hash] = strings.TrimSpace(record[csvColumns.Hash])

		if record[csvColumns.Hash] == "" {
			log.Printf("%#v", record)

			return 0, fmt.Errorf(
				"missing hash for entry %d for %s: %w",
				lineCounter,
				record[csvColumns.Subject],
				err,
			)
		}

		if seen[record[csvColumns.Hash]] {
			log.Printf("Duplicate record on line %d: %v", lineCounter, record[csvColumns.Subject])
			continue
		}
		seen[record[csvColumns.Hash]] = true

		hashes = append(hashes, record[csvColumns.Hash])
	}

	sort.Strings(hashes)

	fh, err := os.Create(filepath.Clean(outputTXTFile))
	if err != nil {
		return 0, err
	}

	defer func() {
		if err := fh.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputTXTFile,
					err,
				)
			}
		}
	}()

	for _, hash := range hashes {
		_, err = io.WriteString(fh, hash+"\n")
		if err != nil {
			return 0, err
		}
	}

	if err := fh.Close(); err != nil {
		return 0, err
	}

	return len(hashes), nil
}

func writeCounterLog(outputFile string, counterLog writtenCounterLog) error {
	fh, err := os.Create(filepath.Clean(outputFile))
	if err != nil {
		return err
	}

	defer func() {
		if err := fh.Close(); err != nil {
			// Ignore "file already closed" errors from our explicit file
			// close attempt at end of this function.
			if !errors.Is(err, os.ErrClosed) {
				log.Printf(
					"error occurred closing file %q: %v",
					outputFile,
					err,
				)
			}
		}
	}()

	if err := tmpl.Execute(fh, counterLog); err != nil {
		return err
	}

	return fh.Close()
}

var tmpl = template.Must(template.New("count.go").Parse(
	`// Code generated by generate.go. DO NOT EDIT.

package intermediates

const (
	expectedCountPublicAllIntermediateCerts           = {{ .PublicAllIntermediateCerts }}
	expectedCountPublicAllIntermediateCertsHashes     = {{ .PublicAllIntermediateCertsHashes }}
	expectedCountMozillaIntermediateCertsReport       = {{ .MozillaIntermediateCertsReport }}
	expectedCountMozillaIntermediateCertsReportHashes = {{ .MozillaIntermediateCertsReportHashes }}
	expectedCountPublicIntermediateCertsRevoked       = {{ .PublicIntermediateCertsRevoked }}
	expectedCountPublicIntermediateCertsRevokedHashes = {{ .PublicIntermediateCertsRevokedHashes }}
)
`))
