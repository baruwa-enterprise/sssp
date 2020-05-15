.PHONY: build clean test help default

BIN_NAME=ssspscan

VERSION := $(shell grep "const Version " cmd/ssspscan/version.go | sed -E 's/.*"(.+)"$$/\1/')
GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_DIRTY=$(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
IMAGE_NAME := "baruwa/ssspscan"

default: test

help:
	@echo 'Management commands for sssp:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile the project.'
	
	@echo '    make clean           Clean the directory tree.'
	@echo

build:
	@echo "building ${BIN_NAME} ${VERSION}"
	@echo "GOPATH=${GOPATH}"
	go build -ldflags "-X main.GitCommit=${GIT_COMMIT}${GIT_DIRTY} -X main.VersionPrerelease=DEV" -o bin/${BIN_NAME} ./cmd/ssspscan

clean:
	@test ! -e bin/${BIN_NAME} || rm bin/${BIN_NAME}

test:
	go test -coverprofile cp.out ./...

test-coverage:
	go tool cover -html=cp.out

