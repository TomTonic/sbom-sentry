# BUILD

This document describes how to build sbom-sentry from source. For installing
a finished release binary, see [INSTALL.md](INSTALL.md).

## Prerequisites

- Go `1.26.2` or newer — see [go.mod](go.mod)
- `git`

## Build

```bash
go build -o sbom-sentry ./cmd/sbom-sentry
```

The resulting binary is statically linked (CGO disabled) and has no external
Go runtime dependencies.

## Install via go install

```bash
go install github.com/sbom-sentry/cmd/sbom-sentry@latest
```

The binary is installed into `$(go env GOPATH)/bin/sbom-sentry`.

## GoReleaser (cross-platform release build)

The project uses [GoReleaser](https://goreleaser.com) to produce all release
artifacts. GoReleaser is configured in [.goreleaser.yml](.goreleaser.yml).

Install GoReleaser (requires `~> v2`):

```bash
brew install goreleaser/tap/goreleaser    # macOS
go install github.com/goreleaser/goreleaser/v2@latest  # any platform
```

Test the release build locally without publishing:

```bash
goreleaser release --snapshot --clean
```

Artifacts appear in `dist/`.

## Running Tests

```bash
go test ./...
go test -race ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

## Running the Linter

```bash
golangci-lint run
```

Configuration: [.golangci.yml](.golangci.yml) (if present).
