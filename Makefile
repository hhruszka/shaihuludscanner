# Project variables
BINARY_NAME := shaihuludscanner
APP_VERSION ?= dev
BUILD_DIR := build
MAIN_PACKAGE := .

# Build metadata
BUILD_TIME := $(shell date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# Go variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod

# Build variables with enhanced metadata
LDFLAGS := -s -w \
	-X main.AppVersion=$(APP_VERSION) \
	-X main.AppName=$(BINARY_NAME) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitCommit=$(GIT_COMMIT) \
	-X main.GitBranch=$(GIT_BRANCH)
CGO_ENABLED := 1

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    # Static linking flags for Linux
    STATIC_FLAGS := -extldflags "-static -lm"
else ifeq ($(UNAME_S),Darwin)
    PLATFORM := darwin
    # macOS doesn't support full static linking, but we can link most things statically
    STATIC_FLAGS := -extldflags "-lm"
else
    PLATFORM := unknown
    STATIC_FLAGS :=
endif

# CGO flags for static linking
CGO_LDFLAGS := -static

# Full ldflags with static linking
LDFLAGS_STATIC := $(LDFLAGS) $(STATIC_FLAGS)

.PHONY: all build build-static clean test deps install help verify check version run test-coverage build-all build-linux build-darwin

## all: Build the project (default target)
all: build-static

## build: Build the binary (dynamically linked)
build:
	@echo "Building $(BINARY_NAME) version $(APP_VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME) \
		$(MAIN_PACKAGE)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

## build-static: Build static binary with yara-x library
build-static:
	@echo "--- Building static $(BINARY_NAME) version $(APP_VERSION) for $(PLATFORM) ---"
	@mkdir -p $(BUILD_DIR)
ifeq ($(PLATFORM),linux)
	CGO_ENABLED=$(CGO_ENABLED) \
	CGO_LDFLAGS="$(CGO_LDFLAGS)" \
	$(GOBUILD) \
		-ldflags "$(LDFLAGS_STATIC)" \
		-tags netgo \
		-a \
		-installsuffix cgo \
		-o $(BUILD_DIR)/$(BINARY_NAME) \
		$(MAIN_PACKAGE)
else
	CGO_ENABLED=$(CGO_ENABLED) \
	$(GOBUILD) \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME) \
		$(MAIN_PACKAGE)
endif
	@echo "--- Build Complete: $(BUILD_DIR)/$(BINARY_NAME) ---"
	@echo "Binary size: $$(du -h $(BUILD_DIR)/$(BINARY_NAME) | cut -f1)"
	@if command -v upx >/dev/null 2>&1; then \
		echo "--- Compressing with UPX ---"; \
		upx --best --lzma $(BUILD_DIR)/$(BINARY_NAME) 2>/dev/null || echo "UPX compression failed or already compressed, continuing..."; \
		echo "Compressed size: $$(du -h $(BUILD_DIR)/$(BINARY_NAME) | cut -f1)"; \
	else \
		echo "--- UPX not found, skipping compression ---"; \
	fi

## build-all: Build for multiple platforms
build-all: build-linux build-darwin

## build-linux: Build static binary for Linux
build-linux:
	@echo "Building static binary for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
	CGO_LDFLAGS="-static" \
	$(GOBUILD) \
		-ldflags "$(LDFLAGS) -extldflags '-static -lm'" \
		-tags netgo \
		-a \
		-installsuffix cgo \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 \
		$(MAIN_PACKAGE)
	@echo "Linux build complete: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

## build-darwin: Build binary for macOS
build-darwin:
	@echo "Building binary for macOS..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 \
	$(GOBUILD) \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 \
		$(MAIN_PACKAGE)
	@echo "macOS AMD64 build complete: $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64"
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
	$(GOBUILD) \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 \
		$(MAIN_PACKAGE)
	@echo "macOS ARM64 build complete: $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64"

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	$(GOCLEAN)
	@echo "Clean complete"

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## install: Install the binary to GOPATH/bin
install: build-static
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

## run: Build and run the application
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

## version: Display version information
version:
	@echo "$(BINARY_NAME) version $(APP_VERSION)"
	@echo "Commit:  $(GIT_COMMIT)"
	@echo "Branch:  $(GIT_BRANCH)"
	@echo "Built:   $(BUILD_TIME)"

## verify: Verify binary and check static linking
verify: build-static
	@echo "--- Verifying Binary ---"
	@echo "File type:"
	@file $(BUILD_DIR)/$(BINARY_NAME)
	@echo ""
ifeq ($(PLATFORM),linux)
	@echo "Linkage check (should show 'not a dynamic executable' for static):"
	@ldd $(BUILD_DIR)/$(BINARY_NAME) 2>&1 || echo "✓ Binary is statically linked"
else ifeq ($(PLATFORM),darwin)
	@echo "Dynamic libraries:"
	@otool -L $(BUILD_DIR)/$(BINARY_NAME)
endif
	@echo ""
	@echo "Binary size:"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME) | awk '{print $$5 " " $$9}'
	@echo ""
	@echo "Build metadata:"
	@echo "  Version: $(APP_VERSION)"
	@echo "  Commit:  $(GIT_COMMIT)"
	@echo "  Branch:  $(GIT_BRANCH)"
	@echo "  Time:    $(BUILD_TIME)"
	@echo ""
	@echo "--- To test, run: ./$(BUILD_DIR)/$(BINARY_NAME) <path-to-scan> ---"

## check: Alias for verify
check: verify

## help: Display this help message
help:
	@echo "$(BINARY_NAME) Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
