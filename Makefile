# SNI-Spoofing-Go — build targets (see README.md § Building)
#
# CLI: CGO_ENABLED=0 everywhere.
# GUI: Wails v2, Node.js, platform WebView deps (README.md § GUI).

LDFLAGS := -s -w
CGO_ENABLED := 0
DIST ?= dist
BUILD_DIR ?= .build
DEV_BIN := $(BUILD_DIR)/sni-spoofing

GO ?= go
GOPATH := $(shell $(GO) env GOPATH)
WAILS := $(GOPATH)/bin/wails
WAILS_VERSION := v2.12.0
GUI_DIR := gui
GUI_WAILS_OUT := $(GUI_DIR)/build/bin
WAILS_FLAGS := -trimpath -clean
WAILS_LINUX_TAGS := -tags webkit2_41
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Linux)
WAILS_NATIVE_EXTRA := $(WAILS_LINUX_TAGS)
endif

# Release GUI paths (CI: make -s gui-asset-<platform>)
GUI_ASSET_LINUX_AMD64 := $(DIST)/sni-spoofing-gui-linux-amd64
GUI_ASSET_LINUX_ARM64 := $(DIST)/sni-spoofing-gui-linux-arm64
GUI_ASSET_WINDOWS_AMD64 := $(DIST)/sni-spoofing-gui-windows-amd64.exe
GUI_ASSET_WINDOWS_ARM64 := $(DIST)/sni-spoofing-gui-windows-arm64.exe
GUI_ASSET_DARWIN := $(DIST)/sni-spoofing-gui-darwin-universal.zip

.PHONY: help all dist dist-checksums clean mod test build \
	windows-amd64 windows-arm64 linux-amd64 linux-arm64 linux-armv7 linux-mipsle linux-mips \
	darwin-amd64 darwin-arm64 \
	install-wails deps-linux gui-frontend \
	gui gui-windows-amd64 gui-windows-arm64 gui-linux-amd64 gui-linux-arm64 \
	gui-darwin-universal gui-dist \
	gui-asset-linux-amd64 gui-asset-linux-arm64 \
	gui-asset-windows-amd64 gui-asset-windows-arm64 gui-asset-darwin-universal

# Default: show targets (run `make build` for local binary)
.DEFAULT_GOAL := help

help:
	@echo "SNI-Spoofing-Go"
	@echo ""
	@echo "  make build          Current GOOS/GOARCH -> $(DEV_BIN)"
	@echo "  make dist | all     All platforms -> $(DIST)/"
	@echo "  make windows-amd64  Windows amd64 -> $(DIST)/sni-spoofing-windows-amd64.exe"
	@echo "  make windows-arm64  Windows arm64 -> $(DIST)/sni-spoofing-windows-arm64.exe"
	@echo "  make linux-amd64    Linux targets -> $(DIST)/sni-spoofing-linux-*"
	@echo "  make linux-arm64"
	@echo "  make linux-armv7    (GOARM=7)"
	@echo "  make linux-mipsle   (GOMIPS=softfloat)"
	@echo "  make linux-mips     (GOMIPS=softfloat)"
	@echo "  make darwin-amd64   macOS Intel  -> $(DIST)/sni-spoofing-darwin-amd64"
	@echo "  make darwin-arm64   macOS Apple  -> $(DIST)/sni-spoofing-darwin-arm64"
	@echo ""
	@echo "  make gui                 GUI for this machine -> $(DIST)/sni-spoofing-gui-*"
	@echo "  make gui-linux-amd64     $(GUI_ASSET_LINUX_AMD64)"
	@echo "  make gui-linux-arm64     $(GUI_ASSET_LINUX_ARM64)"
	@echo "  make gui-windows-amd64   $(GUI_ASSET_WINDOWS_AMD64)"
	@echo "  make gui-windows-arm64   $(GUI_ASSET_WINDOWS_ARM64)"
	@echo "  make gui-darwin-universal  macOS universal zip (run on macOS)"
	@echo "  make gui-dist            all GUI targets (+ macOS on Darwin hosts)"
	@echo ""
	@echo "  make test           go test ./..."
	@echo "  make mod            go mod download"
	@echo "  make install-wails  Install Wails CLI ($(WAILS_VERSION))"
	@echo "  make deps-linux     apt install GTK/WebKit dev libs (Linux, needs sudo)"
	@echo "  make gui-frontend   npm ci in gui/frontend (vite build runs inside wails build)"
	@echo "  make dist-checksums Write $(DIST)/SHA256SUMS"
	@echo "  make clean          remove $(DIST)/, $(BUILD_DIR)/, GUI scratch"

install-wails:
	$(GO) install github.com/wailsapp/wails/v2/cmd/wails@$(WAILS_VERSION)
	@test -x "$(WAILS)" || (echo "Wails CLI not found at $(WAILS); ensure $$(go env GOPATH)/bin is on PATH" >&2; exit 1)

deps-linux:
	sudo apt-get update
	sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev

mod:
	go mod download

test:
	CGO_ENABLED=$(CGO_ENABLED) go test ./...

# Native binary for this machine
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o $(DEV_BIN) .

windows-amd64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-windows-amd64.exe .

windows-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-windows-arm64.exe .

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

darwin-amd64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-darwin-amd64 .

darwin-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-darwin-arm64 .

dist all: windows-amd64 windows-arm64 linux-amd64 linux-arm64 linux-armv7 linux-mipsle linux-mips darwin-amd64 darwin-arm64
	@echo "Done. Binaries in $(DIST)/"
	@ls -lh $(DIST)/

dist-checksums:
	@cd $(DIST) && (ls -A 2>/dev/null | grep -v '^SHA256SUMS$$' | xargs -r sha256sum) > SHA256SUMS

# --- GUI (Wails); scratch in $(GUI_WAILS_OUT)/, release copies in $(DIST)/ ---

# On CI, use the runner npm cache (actions/setup-node). Locally, isolate npm under .build/.
gui-frontend: install-wails
	@mkdir -p $(BUILD_DIR)/tmp
ifneq ($(CI),true)
	@mkdir -p $(BUILD_DIR)/npm-cache $(BUILD_DIR)/npm-home
endif
	cd $(GUI_DIR)/frontend && \
	$(if $(filter true,$(CI)),,\
		HOME="$(CURDIR)/$(BUILD_DIR)/npm-home" \
		TMPDIR="$(CURDIR)/$(BUILD_DIR)/tmp" \
		npm_config_cache="$(CURDIR)/$(BUILD_DIR)/npm-cache" \
		) \
		npm ci

gui: gui-frontend
	@mkdir -p $(DIST)
	cd $(GUI_DIR) && $(WAILS) build $(WAILS_FLAGS) $(WAILS_NATIVE_EXTRA)
	@case "$(UNAME_S)" in \
	  Linux) \
	    case "$(UNAME_M)" in \
	      aarch64|arm64) cp $(GUI_WAILS_OUT)/sni-spoofing-gui $(GUI_ASSET_LINUX_ARM64) ;; \
	      *) cp $(GUI_WAILS_OUT)/sni-spoofing-gui $(GUI_ASSET_LINUX_AMD64) ;; \
	    esac ;; \
	  Darwin) cd $(GUI_WAILS_OUT) && zip -r "$(CURDIR)/$(GUI_ASSET_DARWIN)" sni-spoofing-gui.app ;; \
	  MINGW*|MSYS*|CYGWIN*|Windows*) cp $(GUI_WAILS_OUT)/sni-spoofing-gui.exe $(GUI_ASSET_WINDOWS_AMD64) ;; \
	  *) echo "unsupported host OS for gui staging: $(UNAME_S)"; exit 1 ;; \
	esac

gui-windows-amd64: gui-frontend
	@mkdir -p $(DIST)
	cd $(GUI_DIR) && $(WAILS) build -platform windows/amd64 $(WAILS_FLAGS)
	cp $(GUI_WAILS_OUT)/sni-spoofing-gui.exe $(GUI_ASSET_WINDOWS_AMD64)

gui-windows-arm64: gui-frontend
	@mkdir -p $(DIST)
	cd $(GUI_DIR) && $(WAILS) build -platform windows/arm64 $(WAILS_FLAGS)
	cp $(GUI_WAILS_OUT)/sni-spoofing-gui.exe $(GUI_ASSET_WINDOWS_ARM64)

gui-linux-amd64: gui-frontend
	@mkdir -p $(DIST)
	cd $(GUI_DIR) && $(WAILS) build -platform linux/amd64 $(WAILS_FLAGS) $(WAILS_LINUX_TAGS)
	cp $(GUI_WAILS_OUT)/sni-spoofing-gui $(GUI_ASSET_LINUX_AMD64)

gui-linux-arm64: gui-frontend
	@mkdir -p $(DIST)
	cd $(GUI_DIR) && $(WAILS) build -platform linux/arm64 $(WAILS_FLAGS) $(WAILS_LINUX_TAGS)
	cp $(GUI_WAILS_OUT)/sni-spoofing-gui $(GUI_ASSET_LINUX_ARM64)

gui-darwin-universal: gui-frontend
	@mkdir -p $(DIST)
	cd $(GUI_DIR) && $(WAILS) build -platform darwin/universal $(WAILS_FLAGS)
	cd $(GUI_WAILS_OUT) && zip -r "$(CURDIR)/$(GUI_ASSET_DARWIN)" sni-spoofing-gui.app

gui-asset-linux-amd64:
	@echo $(GUI_ASSET_LINUX_AMD64)

gui-asset-linux-arm64:
	@echo $(GUI_ASSET_LINUX_ARM64)

gui-asset-windows-amd64:
	@echo $(GUI_ASSET_WINDOWS_AMD64)

gui-asset-windows-arm64:
	@echo $(GUI_ASSET_WINDOWS_ARM64)

gui-asset-darwin-universal:
	@echo $(GUI_ASSET_DARWIN)

# linux/arm64 GUI needs a native arm64 host (or ubuntu-24.04-arm CI); skip on x86 Linux.
ifeq ($(UNAME_M),aarch64)
GUI_DIST_EXTRA := gui-linux-arm64
else
GUI_DIST_EXTRA :=
endif

ifeq ($(UNAME_S),Darwin)
gui-dist: gui-windows-amd64 gui-windows-arm64 gui-linux-amd64 $(GUI_DIST_EXTRA) gui-darwin-universal
else
gui-dist: gui-windows-amd64 gui-windows-arm64 gui-linux-amd64 $(GUI_DIST_EXTRA)
endif
	@echo "Done. GUI binaries in $(DIST)/"
	@ls -lh $(DIST)/sni-spoofing-gui-* 2>/dev/null || true

clean:
	rm -rf $(BUILD_DIR) dist-gui
	rm -f sni-spoofing sni-spoofing.exe sni-spoofing-windows-amd64.exe sni-spoofing-windows-arm64.exe
	rm -rf $(GUI_WAILS_OUT)
	find $(GUI_DIR)/frontend/dist -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
	rm -rf $(GUI_DIR)/frontend/wailsjs $(GUI_DIR)/frontend/package.json.md5
	rm -f $(DIST)/sni-spoofing* $(DIST)/SHA256SUMS
	@-rmdir $(DIST) 2>/dev/null || true
