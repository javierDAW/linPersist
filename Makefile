# linpersist Makefile
#
# Build, test and verification targets for the linpersist agent.
# Reproducibility flags (-trimpath, -buildvcs=false) and version stamping
# are pinned here. CGO is disabled everywhere; if any dependency drags in
# CGO, the static-link check in tools/verify_static.sh will fail the build.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
# -tags uses the comma form (osusergo,netgo) so the same value can be
# pasted into a shell variable or array without re-quoting headaches.
GOFLAGS := -trimpath -buildvcs=false -tags=osusergo,netgo

# linux/<arch>[/<goarm>]
TARGETS := linux/amd64 linux/arm64 linux/386 linux/arm/7

.PHONY: all build build-all verify test test-race lint fmt audit detgen detgen-verify clean help

# The set of cmd/<NAME> binaries the build system knows about. Adding a
# new top-level binary is a one-line edit here plus the cmd/<name>/
# package.
BINARIES := linpersist linpersist-report

all: lint test audit detgen-verify build

build:
	@for b in $(BINARIES); do \
	  echo ">> dist/$$b"; \
	  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$$b ./cmd/$$b || exit 1; \
	done

build-all:
	@mkdir -p dist
	@for b in $(BINARIES); do \
	  for t in $(TARGETS); do \
	    os=$$(echo $$t | cut -d/ -f1); \
	    arch=$$(echo $$t | cut -d/ -f2); \
	    goarm=$$(echo $$t | cut -d/ -f3); \
	    suffix=""; \
	    [ -n "$$goarm" ] && suffix="v$$goarm"; \
	    out=dist/$$b-$$os-$$arch$$suffix; \
	    echo ">> $$out"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$goarm \
	      go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $$out ./cmd/$$b || exit 1; \
	  done; \
	done

verify:
	@for b in $(BINARIES); do \
	  echo ">> verify dist/$$b-linux-amd64"; \
	  ./tools/verify_static.sh dist/$$b-linux-amd64 || exit 1; \
	done

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

lint:
	go vet ./...
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
	  echo "gofmt: files need formatting:" >&2; \
	  echo "$$out" >&2; \
	  exit 1; \
	fi

fmt:
	gofmt -w .

# audit is the release gate from ADR-0001: it diffs matrix.yaml against
# the modules the code actually emits. Fails on drift; prints a
# one-line summary on success.
audit:
	go run ./cmd/matrix-audit

# detgen rewrites tools/stack_demo.sql Q7 block from detections.yaml.
# Run after editing internal/detections/detections.yaml; commit both
# files together. See ADR-0013.
detgen:
	go run ./cmd/detgen

# detgen-verify is the release gate from ADR-0013: it fails if the
# committed Q7 block in tools/stack_demo.sql does not match what
# would be regenerated from detections.yaml. Catches the situation
# where someone edits the YAML but forgets to regenerate the SQL.
detgen-verify:
	go run ./cmd/detgen --verify

clean:
	rm -rf dist/

help:
	@echo "Targets:"
	@echo "  build      build native binary into dist/linpersist"
	@echo "  build-all  cross-compile for $(TARGETS)"
	@echo "  verify     run static-link gate against dist/linpersist-linux-amd64"
	@echo "  test       run unit tests"
	@echo "  test-race  run unit tests with -race"
	@echo "  lint       run go vet and gofmt check"
	@echo "  fmt        run gofmt -w"
	@echo "  audit      matrix.yaml <-> code drift gate (ADR-0001)"
	@echo "  detgen     regenerate Q7 SQL block from detections.yaml"
	@echo "  detgen-verify  drift gate for detections.yaml <-> stack_demo.sql (ADR-0013)"
	@echo "  clean      remove dist/"
