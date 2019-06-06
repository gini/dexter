# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Based on https://github.com/thockin/go-build-template

##-------------------------------------------------
## Variables you may need to tweak
##-------------------------------------------------

# The binary to build (just the basename).
BIN := dexter

# This repo's root import path (under GOPATH).
PKG := github.com/gini/dexter

# Where to push the docker image.
REGISTRY ?=

# Which architecture to build - see $(ALL_ARCH) for options.
ARCH ?= amd64

ALL_ARCH := amd64

# Which OS to build
OS ?= darwin

# Artefact to create
ARTIFACT ?= build/$(BIN)_$(OS)_$(ARCH)

# Git hash
GIT_HASH = $(shell git rev-parse HEAD)

# Set version
VERSION := $(shell git describe --tags --always --dirty)

# Set DOB (Day Of Birth)
DOB := $(shell date +%s)

##-------------------------------------------------
## These variables should not need tweaking
##-------------------------------------------------

IMAGE := $(REGISTRY)/$(BIN)-$(ARCH)

CGO_ENABLED := 0

SHELL := /bin/bash

##-------------------------------------------------
## Rules
##-------------------------------------------------

.PHONY: version

# If you want to build all binaries, see the 'all-build' rule.
all: vet test build

# Shortcut to build assets for arch
build-%:
	@$(MAKE) --no-print-directory ARCH=$* build

# Builds all defined architectures
all-build: $(addprefix build-, $(ALL_ARCH))

# Build default architecture (amd64)
build: bin/$(ARCH)/$(BIN)

# Do a real build for the given arch and binary
bin/$(ARCH)/$(BIN):
	@echo "building: $@"
	CGO_ENABLED=$(CGO_ENABLED) \
	GOOS=$(OS) \
	GOARCH=$(ARCH) \
	go build \
	  -o $(ARTIFACT) \
	  -ldflags "-X $(PKG)/version.VERSION=$(VERSION) \
	    -X $(PKG)/version.GITHASH=$(GIT_HASH) \
	    -X $(PKG)/version.DOB=$(DOB) \
	    -X $(PKG)/cmd.defaultClientID=$(CLIENT_ID) \
	    -X $(PKG)/cmd.defaultClientSecret=$(CLIENT_SECRET) \
      -s -w"

kubeauth: embed build kubeauth_complete  # NOTE: run make with -k to ensure unembedding of files, e.g. `make -k kubeauth`. Otherwise you run the risk of commiting creds into the repo.

# embed the creds into the executable, but keep them out of the repo.
embed:
	if [ ! -d tmp ]; then \
  	mkdir tmp; \
		echo tmp >> .gitignore; \
  fi; 
	cp -pv vendor/golang.org/x/oauth2/okta/okta.go tmp; 
	cp -pv cmd/auth.go tmp; 
	sed -i -e 's,OIDC_ENDPOINT,$(OIDC_ENDPOINT),g' ./vendor/golang.org/x/oauth2/okta/okta.go; 
	sed -i -e 's,OIDC_CLIENT_ID,$(OIDC_CLIENT_ID),g' cmd/auth.go; 
	sed -i -e 's,OIDC_CLIENT_SECRET,$(OIDC_CLIENT_SECRET),g' cmd/auth.go 
	sed -i -e 's,OIDC_CALLBACK,$(OIDC_CALLBACK),g' cmd/auth.go 

unembed:
	echo "unembedding kubeauth vars..." &&  cp -pv tmp/okta.go vendor/golang.org/x/oauth2/okta/okta.go && cp -pv tmp/auth.go cmd/auth.go; 
kubeauth_complete: 
	case "$$?" in  \
	0)  \
		echo "Installing kubeauth ..." && cp -pv build/dexter_darwin_amd64 bin/kubeauth; \
		echo "unembedding kubeauth vars..." &&  cp -pv tmp/okta.go vendor/golang.org/x/oauth2/okta/okta.go && cp -pv tmp/auth.go cmd/auth.go; \
		;; \
	*)  \
		echo "unembedding kubeauth vars..." &&  cp -pv tmp/okta.go vendor/golang.org/x/oauth2/okta/okta.go && cp -pv tmp/auth.go cmd/auth.go; \
		;; \
	esac

# Run go vet on repo
vet:
	@echo "vet package $(PKG)"
	@go vet -v

# Execute test suite
test: vet
	@echo "test package $(PKG)"
	@go test -v

# Output the generated version string
version:
	@echo $(VERSION)

# Cleanup
clean:
	rm -f $(ARTIFACT)
