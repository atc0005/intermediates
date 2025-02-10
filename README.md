<!-- omit in toc -->
# atc0005/intermediates

Package intermediates embeds a list of known unexpired, unrevoked
intermediate certificates chaining to roots with Websites trust in the
Mozilla Root Program.

[![Latest Release](https://img.shields.io/github/release/atc0005/intermediates.svg?style=flat-square)](https://github.com/atc0005/intermediates/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/atc0005/intermediates.svg)](https://pkg.go.dev/github.com/atc0005/intermediates)
[![go.mod Go version](https://img.shields.io/github/go-mod/go-version/atc0005/intermediates)](https://github.com/atc0005/intermediates)

<!-- omit in toc -->
## Table of Contents

- [Project home](#project-home)
- [Overview](#overview)
- [Contributions](#contributions)
- [Origin](#origin)
- [License](#license)
- [References](#references)
  - [Upstream](#upstream)
  - [Related projects](#related-projects)

## Project home

See [our GitHub repo][repo-url] for the latest code.

## Overview

From the upstream repo's overview:

> Package intermediates embeds a list of known unexpired, unrevoked
intermediate certificates chaining to roots with Websites trust in the
Mozilla Root Program.
>
> This dataset is useful to establish connections to misconfigured servers that
fail to provide a full certificate chain but provide a valid, publicly
trusted end-entity certificate. Some browsers implement similar strategies to
successfully establish connections to these sites.

This project applies light changes to the upstream project intended to support
work in the `atc0005/check-cert` and `atc0005/cert-payload` projects. The
current intent is to mothball this project if/when the upstream project
provides similar functionality.

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

See the [LICENSE](LICENSE) file for details.

From the upstream repo's overview:

> This is not an official or supported Google product, just some code that
happens to be owned by Google.

## References

### Upstream

- <https://pkg.go.dev/filippo.io/intermediates>
- <https://github.com/FiloSottile/intermediates>

### Related projects

- <https://github.com/atc0005/check-cert>
- <https://github.com/atc0005/cert-payload>

<!-- Footnotes here  -->

[repo-url]: <https://github.com/atc0005/intermediates>  "This project's GitHub repo"
