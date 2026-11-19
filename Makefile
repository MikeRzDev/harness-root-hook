# psudo build and release. Nothing here runs automatically: there is no CI.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

.PHONY: build test dist release install-claude-code install-codex uninstall-claude-code uninstall-codex clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/psudo ./cmd/psudo

test:
	go vet ./...
	go test ./...

dist: test
	rm -rf dist
	mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; name=psudo_$(VERSION)_$${os}_$${arch}; \
		mkdir -p dist/$$name; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/psudo ./cmd/psudo || exit 1; \
		cp LICENSE README.md dist/$$name/; \
		tar -C dist -czf dist/$$name.tar.gz $$name || exit 1; \
		echo "built dist/$$name.tar.gz"; \
	done
	cd dist && shasum -a 256 *.tar.gz > SHA256SUMS

# Publishes a GitHub release from local artifacts. Run only on purpose:
#   git tag v1.0.0 && make release VERSION=v1.0.0
release: dist
	gh release create $(VERSION) dist/*.tar.gz dist/SHA256SUMS --title "psudo $(VERSION)" --generate-notes

install-claude-code: build
	bin/psudo --install=claude-code

install-codex: build
	bin/psudo --install=codex

uninstall-claude-code: build
	bin/psudo --uninstall=claude-code

uninstall-codex: build
	bin/psudo --uninstall=codex

clean:
	rm -rf bin dist
