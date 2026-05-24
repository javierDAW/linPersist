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

.PHONY: all build build-all verify test test-race lint fmt audit detgen detgen-verify matrix-sync-verify clean help engagement-kit

# Engagement-kit targets: subset of build-all (amd64 + arm64 only;
# 386 and arm-v7 are niche and shipped on request) plus the operator-
# side analysis tool. The kit's filename embeds VERSION so multiple
# engagements can co-exist on disk without overwriting each other.
KIT_TARGETS := linux/amd64 linux/arm64
KIT_NAME    := linpersist-$(VERSION)-engagement-kit
KIT_STAGE   := dist/$(KIT_NAME)

# The set of cmd/<NAME> binaries the build system knows about. Adding a
# new top-level binary is a one-line edit here plus the cmd/<name>/
# package.
BINARIES := linpersist linpersist-report

all: lint test audit detgen-verify matrix-sync-verify build

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

# matrix-sync-verify enforces that the matrix.yaml embedded in
# cmd/linpersist-report (via go:embed for the MITRE coverage
# panel) matches the canonical matrix.yaml at the repo root.
# Re-sync with: cp matrix.yaml cmd/linpersist-report/assets/matrix.yaml
matrix-sync-verify:
	@if ! cmp -s matrix.yaml cmd/linpersist-report/assets/matrix.yaml; then \
		echo "matrix-sync-verify: drift between matrix.yaml and cmd/linpersist-report/assets/matrix.yaml"; \
		echo "Re-sync with: cp matrix.yaml cmd/linpersist-report/assets/matrix.yaml"; \
		exit 1; \
	fi
	@echo "matrix-sync-verify: in sync"


# engagement-kit packages a consultoría-ready deliverable:
#   - linpersist agent (amd64 + arm64)
#   - linpersist-report analyst tool (amd64 + arm64)
#   - RUNBOOK.md  (docs/client-runbook.md, bilingual)
#   - SCOPE.md    (docs/scope.md, SOW-ready)
#   - LICENSE + README + CHANGELOG
#   - sample-report.{html,txt}  (committed goldens, as reference)
#   - CHECKSUMS.txt  (sha256 of every file in the kit)
#
# Output: dist/$(KIT_NAME).tar.gz
#
# The target fails loudly if the docs are missing so the kit never
# ships incomplete. Re-build with `make engagement-kit VERSION=v0.5.0`.
engagement-kit:
	@[ -f docs/client-runbook.md ] || { echo "ERR: docs/client-runbook.md missing"; exit 1; }
	@[ -f docs/scope.md ]          || { echo "ERR: docs/scope.md missing"; exit 1; }
	@[ -f LICENSE ]                || { echo "ERR: LICENSE missing"; exit 1; }
	@rm -rf $(KIT_STAGE)
	@mkdir -p $(KIT_STAGE)
	@echo ">> building binaries for $(KIT_TARGETS)"
	@for b in $(BINARIES); do \
	  for t in $(KIT_TARGETS); do \
	    os=$$(echo $$t | cut -d/ -f1); \
	    arch=$$(echo $$t | cut -d/ -f2); \
	    out=$(KIT_STAGE)/$$b-$$os-$$arch; \
	    echo "   $$out"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	      go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $$out ./cmd/$$b || exit 1; \
	  done; \
	done
	@echo ">> staging docs and samples"
	@cp README.md $(KIT_STAGE)/
	@cp CHANGELOG.md $(KIT_STAGE)/
	@cp LICENSE $(KIT_STAGE)/
	@cp docs/client-runbook.md $(KIT_STAGE)/RUNBOOK.md
	@cp docs/scope.md $(KIT_STAGE)/SCOPE.md
	@cp internal/testdata/golden/stats/build_smoke.html.golden $(KIT_STAGE)/sample-report.html
	@cp internal/testdata/golden/stats/build_smoke.text.golden $(KIT_STAGE)/sample-report.txt
	@echo ">> generating CHECKSUMS.txt"
	@cd $(KIT_STAGE) && sha256sum * > CHECKSUMS.txt
	@echo ">> packing tarball"
	@cd dist && tar czf $(KIT_NAME).tar.gz $(KIT_NAME)/
	@rm -rf $(KIT_STAGE)
	@echo ""
	@echo "engagement-kit ready:"
	@ls -lh dist/$(KIT_NAME).tar.gz

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
	@echo "  engagement-kit pack a consultoría deliverable into dist/$(KIT_NAME).tar.gz"
	@echo "  clean      remove dist/"
