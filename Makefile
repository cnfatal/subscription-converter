APP := subscription-converter
LABEL := cn.fatalc.subscription-converter
BIN_DIR := $(CURDIR)/bin
BINARY := $(BIN_DIR)/$(APP)
CONFIG ?= $(CURDIR)/config.yaml
PATCH_FILE ?= $(CURDIR)/rules/proxy-rules.yaml

USER_ID := $(shell id -u)
LAUNCH_DOMAIN := gui/$(USER_ID)
SERVICE_DIR := $(HOME)/Library/Application Support/$(APP)
SERVICE_BINARY := $(SERVICE_DIR)/$(APP)
SERVICE_CONFIG := $(SERVICE_DIR)/config.yaml
SERVICE_RULES_DIR := $(SERVICE_DIR)/rules
SERVICE_PATCH_FILE := $(SERVICE_RULES_DIR)/proxy-rules.yaml
LAUNCH_AGENTS_DIR := $(HOME)/Library/LaunchAgents
SERVICE_PLIST := $(LAUNCH_AGENTS_DIR)/$(LABEL).plist
PLIST_TEMPLATE := $(CURDIR)/packaging/macos/$(LABEL).plist.in

.PHONY: help build test vet run clean \
	launchd-install launchd-sync-config launchd-restart launchd-status \
	launchd-uninstall

help:
	@echo "Targets:"
	@echo "  build                 Build $(BINARY)"
	@echo "  test                  Run tests"
	@echo "  vet                   Run go vet"
	@echo "  run                   Run the server with CONFIG=$(CONFIG)"
	@echo "  launchd-install       Install APP, CONFIG, and PATCH_FILE"
	@echo "  launchd-sync-config   Copy CONFIG and PATCH_FILE, then restart"
	@echo "  launchd-restart       Restart the LaunchAgent"
	@echo "  launchd-status        Print LaunchAgent status"
	@echo "  launchd-uninstall     Stop and remove the LaunchAgent"

build:
	@mkdir -p "$(BIN_DIR)"
	CGO_ENABLED=0 go build -trimpath -o "$(BINARY)" ./cmd/subscription-converter

test:
	go test ./...

vet:
	go vet ./...

run: build
	"$(BINARY)" serve -config "$(CONFIG)"

clean:
	rm -f "$(BINARY)"

launchd-install: build
	@test -f "$(CONFIG)" || { echo "missing $(CONFIG); copy config.example.yaml and configure it first"; exit 1; }
	@test -f "$(PATCH_FILE)" || { echo "missing $(PATCH_FILE)"; exit 1; }
	@mkdir -p "$(SERVICE_DIR)" "$(SERVICE_RULES_DIR)" "$(LAUNCH_AGENTS_DIR)"
	/usr/bin/install -m 755 "$(BINARY)" "$(SERVICE_BINARY)"
	/usr/bin/install -m 600 "$(CONFIG)" "$(SERVICE_CONFIG)"
	/usr/bin/install -m 600 "$(PATCH_FILE)" "$(SERVICE_PATCH_FILE)"
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

launchd-sync-config:
	@test -f "$(CONFIG)" || { echo "missing $(CONFIG)"; exit 1; }
	@test -f "$(PATCH_FILE)" || { echo "missing $(PATCH_FILE)"; exit 1; }
	@mkdir -p "$(SERVICE_DIR)" "$(SERVICE_RULES_DIR)"
	/usr/bin/install -m 600 "$(CONFIG)" "$(SERVICE_CONFIG)"
	/usr/bin/install -m 600 "$(PATCH_FILE)" "$(SERVICE_PATCH_FILE)"
	launchctl kickstart -k "$(LAUNCH_DOMAIN)/$(LABEL)"

launchd-restart:
	launchctl kickstart -k "$(LAUNCH_DOMAIN)/$(LABEL)"

launchd-status:
	launchctl print "$(LAUNCH_DOMAIN)/$(LABEL)"

launchd-uninstall:
	@launchctl bootout "$(LAUNCH_DOMAIN)/$(LABEL)" >/dev/null 2>&1 || true
	rm -f "$(SERVICE_PLIST)"
	@echo "uninstalled $(LABEL); retained $(SERVICE_DIR)"
