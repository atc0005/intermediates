<!-- omit in toc -->
# atc0005/intermediates

Package intermediates provides embedded hashes and intermediate certificates
chaining to roots in the Mozilla Root Program.

[![Latest Release](https://img.shields.io/github/release/atc0005/intermediates.svg?style=flat-square)](https://github.com/atc0005/intermediates/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/atc0005/intermediates/v2.svg)](https://pkg.go.dev/github.com/atc0005/intermediates/v2)
[![go.mod Go version](https://img.shields.io/github/go-mod/go-version/atc0005/intermediates)](https://github.com/atc0005/intermediates)

<!-- omit in toc -->
## Table of Contents

- [Project home](#project-home)
- [Overview](#overview)
  - [`v1` branch](#v1-branch)
  - [`v2` series](#v2-series)
- [Recommendations](#recommendations)
- [Stability](#stability)
- [Use cases](#use-cases)
- [Contributions](#contributions)
- [Origin](#origin)
- [License](#license)
  - [Original project + changes](#original-project--changes)
  - [Mozilla intermediate certificates](#mozilla-intermediate-certificates)
- [References](#references)
  - [Upstream](#upstream)
  - [Related projects](#related-projects)

## Project home

See [our GitHub repo][repo-url] for the latest code.

## Overview

### `v1` branch

This branch applies light changes to the upstream project to provide automated
tags and releases. The goal was to make it easier for dependent projects to
maintain current versions of the intermediates bundle (e.g., via Dependabot's
support for generating PRs based on dependency tags).

Further work on this branch is paused in favor of breaking changes applied in
later series. See the README doc in the `development` or `master` branches for
the latest information. If there is sufficient interest we can re-enable
automatic releases for this series. Please [open a
discussion](https://github.com/atc0005/intermediates/discussions/new/choose)
or add to an existing one to share your feedback.

### `v2` series

The `v2` series of releases is a big change in focus for the project.

Instead of providing an opaque `*x509.CertPool` and a `VerifyConnection`
callback for use with a `tls.Config` for a client connection, this series of
releases drops that support and provides direct access to collections of
intermediate certificates and hashes for direct use by clients.

The `v2` series provides:

- valid intermediate certificates and expired intermediate certificates but
  not revoked intermediate certificates which chain to root certificates in
  Mozilla's program
- known unexpired, unrevoked intermediate certificates chaining to roots with
  Websites trust in the Mozilla Root Program
- revoked intermediate CA certificates which chained to roots in the Mozilla
  Root Program
- certificate hashes for all sets

The audience for this functionality is primarily diagnostic tools which need
direct access to `x509.Certificate` values for certificate chain analysis
purposes.

See the linked documentation for more information.

## Recommendations

- It's recommended that only binaries, and not libraries, import this package
- For best results this package should be kept up to date using tools such as
  Dependabot

## Stability

This package went through a lot of changes for the `v2` series. While the
intent is to provide stable backwards compatible changes going forward, the
current audience for this package is the `atc0005/check-cert` project which is
itself going through a lot of changes. As a result, this package may go
through further disruptive changes to accommodate that project's needs.

It is recommended that you do not use branches directly and instead only use
release tags. Until this package's design stabilizes current branches may
provide mixed results.

## Use cases

The provided intermediate certificates are useful to establish connections to
misconfigured servers that fail to provide a full certificate chain but
provide a valid, publicly trusted end-entity certificate. Some browsers
implement similar strategies to successfully establish connections to these
sites. This collection may not be necessary for this purpose if using the
system roots on certain operating systems, as the platform verifier might have
its own mechanism to fetch missing intermediates.

Another use case (and arguably the primary purpose) for the provided
intermediates and intermediate hashes is diagnostic tools which evaluate
certificate chains for common misconfiguration issues. The intermediate
certificate collections allow bridging incomplete chains to a trusted root CA
certificate.

The collections of intermediate hashes are useful for identifying which of the
three collections an existing intermediate certificate belongs to.

## Contributions

This project has a very narrow focus. While PRs may be accepted to resolve
typos, logic errors and enhance documentation, behavioral changes and feature
additions will likely be rejected as out of scope. If there is any doubt,
please open a new discussion and ask for feedback.

## Origin

This project is a fork of `filippo.io/intermediates`:

- <https://pkg.go.dev/filippo.io/intermediates>
- <https://github.com/FiloSottile/intermediates>

## License

### Original project + changes

See the [LICENSE](LICENSE) file for details regarding code/assets.

From the original upstream `filippo.io/intermediates` repo's overview:

> This is not an official or supported Google product, just some code that
happens to be owned by Google.

### Mozilla intermediate certificates

See <https://www.ccadb.org/rootstores/usage#ccad> and/or the
`mozilla_reports/CDLA-Permissive-2.0.txt` license file for details regarding
the intermediate CA reports provided by the Mozilla project.

## References

### Upstream

- <https://pkg.go.dev/filippo.io/intermediates>
- <https://github.com/FiloSottile/intermediates>

### Related projects

- <https://github.com/atc0005/check-cert>
- <https://github.com/atc0005/cert-payload>

<!-- Footnotes here  -->

[repo-url]: <https://github.com/atc0005/intermediates>  "This project's GitHub repo"
