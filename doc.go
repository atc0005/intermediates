// Copyright 2021 Google LLC
// Copyright 2025 Adam Chalkley
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package intermediates provides embedded:
//
//   - valid intermediate certificates and expired intermediate certificates
//     but not revoked intermediate certificates which chain to root
//     certificates in Mozilla's program
//   - known unexpired, unrevoked intermediate certificates chaining to
//     roots with Websites trust in the Mozilla Root Program
//   - revoked intermediate CA certificates which chained to roots in the
//     Mozilla Root Program
//   - certificate hashes for all three sets
//
// # Recommendations
//
//   - It's recommended that only binaries, and not libraries, import this
//     package
//   - For best results this package should be kept up to date using tools
//     such as Dependabot
//
// # Use cases
//
// The provided intermediate certificates are useful to establish connections
// to misconfigured servers that fail to provide a full certificate chain but
// provide a valid, publicly trusted end-entity certificate. Some browsers
// implement similar strategies to successfully establish connections to these
// sites. This collection may not be necessary for this purpose if using the
// system roots on certain operating systems, as the platform verifier might
// have its own mechanism to fetch missing intermediates.
//
// Another use case for the provided intermediates and intermediate hashes is
// diagnostic tools which evaluate certificate chains for common
// misconfiguration issues. The intermediate certificate collections allow
// bridging incomplete chains to a trusted root CA certificate.
//
// The collections of intermediate hashes are useful for identifying which of
// the three collections an existing intermediate certificate belongs to.
package intermediates
