# SNI-Spoofing-Go — build targets (see BUILD.md for prerequisites and usage)
#
# Pure Go: CGO_ENABLED=0 everywhere.

LDFLAGS := -s -w
CGO_ENABLED := 0
DIST ?= dist

# WinDivert official release (basil00/WinDivert) — x64 DLL + sys copied into $(DIST)
WINDIVERT_VERSION ?= 2.2.2
WINDIVERT_ZIP = WinDivert-$(WINDIVERT_VERSION)-A.zip
WINDIVERT_EXTRACT = WinDivert-$(WINDIVERT_VERSION)-A
WINDIVERT_URL = https://github.com/basil00/WinDivert/releases/download/v$(WINDIVERT_VERSION)/$(WINDIVERT_ZIP)
WINDIVERT_CACHE ?= $(CURDIR)/.cache/windivert

.PHONY: help all dist clean mod test build windivert windows-bundle \
	windows linux-amd64 linux-arm64 linux-armv7 linux-mipsle linux-mips

# Default: show targets (run `make build` for local binary)
.DEFAULT_GOAL := help

help:
	@echo "SNI-Spoofing-Go"
	@echo ""
	@echo "  make build          Current GOOS/GOARCH -> ./sni-spoofing"
	@echo "  make dist | all     All platforms -> $(DIST)/"
	@echo "  make windows        Windows amd64 -> $(DIST)/sni-spoofing.exe"
	@echo "  make linux-amd64    Linux targets -> $(DIST)/sni-spoofing-linux-*"
	@echo "  make linux-arm64"
	@echo "  make linux-armv7    (GOARM=7)"
	@echo "  make linux-mipsle   (GOMIPS=softfloat)"
	@echo "  make linux-mips     (GOMIPS=softfloat)"
	@echo "  make test           go test ./..."
	@echo "  make mod            go mod download"
	@echo "  make windivert      fetch WinDivert x64 DLL/sys into $(DIST)/"
	@echo "  make windows-bundle windows + windivert for $(DIST)/"
	@echo "  make clean          remove $(DIST)/ and ./sni-spoofing"

mod:
	go mod download

test:
	CGO_ENABLED=$(CGO_ENABLED) go test ./...

# Native binary for this machine (name: sni-spoofing)
build:
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o sni-spoofing .

windows:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing.exe .

# WinDivert runtime for Windows amd64 (official GitHub release; not committed — see .gitignore)
windivert:
	@set -e; \
	mkdir -p "$(WINDIVERT_CACHE)" "$(DIST)"; \
	if [ ! -f "$(WINDIVERT_CACHE)/$(WINDIVERT_ZIP)" ]; then \
		echo "Downloading $(WINDIVERT_URL)"; \
		if command -v curl >/dev/null 2>&1; then \
			curl -fsSL -o "$(WINDIVERT_CACHE)/$(WINDIVERT_ZIP)" "$(WINDIVERT_URL)"; \
		elif command -v wget >/dev/null 2>&1; then \
			wget -q -O "$(WINDIVERT_CACHE)/$(WINDIVERT_ZIP)" "$(WINDIVERT_URL)"; \
		else \
			echo "windivert: need curl or wget" >&2; exit 1; \
		fi; \
	fi; \
	rm -rf "$(WINDIVERT_CACHE)/$(WINDIVERT_EXTRACT)"; \
	unzip -q -o "$(WINDIVERT_CACHE)/$(WINDIVERT_ZIP)" -d "$(WINDIVERT_CACHE)"; \
	cp "$(WINDIVERT_CACHE)/$(WINDIVERT_EXTRACT)/x64/WinDivert.dll" "$(DIST)/"; \
	cp "$(WINDIVERT_CACHE)/$(WINDIVERT_EXTRACT)/x64/WinDivert64.sys" "$(DIST)/"; \
	echo "WinDivert $(WINDIVERT_VERSION) x64: WinDivert.dll + WinDivert64.sys -> $(DIST)/"

windows-bundle: windows windivert
	@echo "Windows bundle: $(DIST)/sni-spoofing.exe + WinDivert.dll + WinDivert64.sys"

linux-amd64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-amd64 .

linux-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-arm64 .

linux-armv7:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm GOARM=7 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-armv7 .

linux-mipsle:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-mipsle .

linux-mips:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mips GOMIPS=softfloat \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-mips .

dist all: windows linux-amd64 linux-arm64 linux-armv7 linux-mipsle linux-mips
	@echo "Done. Binaries in $(DIST)/"
	@ls -lh $(DIST)/

clean:
	rm -f sni-spoofing
	rm -f $(DIST)/sni-spoofing.exe $(DIST)/sni-spoofing-linux-amd64 $(DIST)/sni-spoofing-linux-arm64 \
		$(DIST)/sni-spoofing-linux-armv7 $(DIST)/sni-spoofing-linux-mipsle $(DIST)/sni-spoofing-linux-mips
	@-rmdir $(DIST) 2>/dev/null || true
