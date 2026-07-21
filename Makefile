APP := subscription-converter
LABEL := cn.fatalc.subscription-converter
BIN_DIR := $(CURDIR)/bin
BINARY := $(BIN_DIR)/$(APP)
CONFIG ?= $(CURDIR)/config.yaml
PATCH_FILE ?= $(CURDIR)/rules/proxy-rules.yaml

IMAGE ?= ghcr.io/cnfatal/$(APP)
TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64
IMAGE_ARCHES := amd64 arm64

USER_ID := $(shell id -u)
LAUNCH_DOMAIN := gui/$(USER_ID)
SERVICE_DIR := $(HOME)/Library/Application Support/$(APP)
SERVICE_BINARY := $(SERVICE_DIR)/$(APP)
SERVICE_CONFIG := $(SERVICE_DIR)/config.yaml
SERVICE_RULES_DIR := $(SERVICE_DIR)/rules
LAUNCH_AGENTS_DIR := $(HOME)/Library/LaunchAgents
SERVICE_PLIST := $(LAUNCH_AGENTS_DIR)/$(LABEL).plist
PLIST_TEMPLATE := $(CURDIR)/packaging/macos/$(LABEL).plist.in

.PHONY: help build test vet run clean launchd-install launchd-uninstall image

help:
	@echo "Targets:"
	@echo "  build       Build host and Linux image binaries"
	@echo "  test        Run tests"
	@echo "  vet         Run go vet"
	@echo "  run         Run the server with CONFIG=$(CONFIG)"
	@echo "  launchd-install     Install and start the macOS LaunchAgent"
	@echo "  launchd-uninstall   Stop and remove the macOS LaunchAgent"
	@echo "  image       Build and push $(IMAGE):$(TAG) for $(PLATFORMS)"

build:
	@mkdir -p "$(BIN_DIR)"
	CGO_ENABLED=0 go build -trimpath -o "$(BINARY)" ./cmd/subscription-converter
	@for arch in $(IMAGE_ARCHES); do \
		mkdir -p "$(BIN_DIR)/linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags="-s -w" \
			-o "$(BIN_DIR)/linux/$$arch/$(APP)" ./cmd/subscription-converter; \
	done

test:
	go test ./...

vet:
	go vet ./...

run: build
	"$(BINARY)" serve -config "$(CONFIG)"

clean:
	rm -rf "$(BIN_DIR)"

launchd-install: build
	@test "$$(uname -s)" = "Darwin" || { echo "install is supported on macOS only"; exit 1; }
	@test -f "$(CONFIG)" || { echo "missing $(CONFIG); copy config.example.yaml and configure it first"; exit 1; }
	@mkdir -p "$(SERVICE_DIR)" "$(SERVICE_RULES_DIR)" "$(LAUNCH_AGENTS_DIR)"
	/usr/bin/install -m 755 "$(BINARY)" "$(SERVICE_BINARY)"
	/usr/bin/install -m 600 "$(CONFIG)" "$(SERVICE_CONFIG)"
	@if test -f "$(PATCH_FILE)"; then /usr/bin/install -m 600 "$(PATCH_FILE)" "$(SERVICE_RULES_DIR)/proxy-rules.yaml"; fi
	@sed \
		-e 's|@BINARY@|$(SERVICE_BINARY)|g' \
		-e 's|@CONFIG@|$(SERVICE_CONFIG)|g' \
		-e 's|@WORKING_DIRECTORY@|$(SERVICE_DIR)|g' \
		"$(PLIST_TEMPLATE)" > "$(SERVICE_PLIST)"
	@plutil -lint "$(SERVICE_PLIST)"
	@launchctl bootout "$(LAUNCH_DOMAIN)/$(LABEL)" >/dev/null 2>&1 || true
	launchctl bootstrap "$(LAUNCH_DOMAIN)" "$(SERVICE_PLIST)"
	launchctl kickstart -k "$(LAUNCH_DOMAIN)/$(LABEL)"
	@echo "installed $(LABEL)"

launchd-uninstall:
	@test "$$(uname -s)" = "Darwin" || { echo "uninstall is supported on macOS only"; exit 1; }
	@launchctl bootout "$(LAUNCH_DOMAIN)/$(LABEL)" >/dev/null 2>&1 || true
	rm -f "$(SERVICE_PLIST)"
	@echo "uninstalled $(LABEL); retained $(SERVICE_DIR)"

image:
	@for arch in $(IMAGE_ARCHES); do \
		test -x "$(BIN_DIR)/linux/$$arch/$(APP)" || { echo "missing Linux binaries; run make build first"; exit 1; }; \
	done
	docker buildx build --platform "$(PLATFORMS)" --tag "$(IMAGE):$(TAG)" --push .
