# Go Options
MODULE       := github.com/seeeverything/notary-gcr
LDFLAGS      := -w -s
COVEROUT     := ./coverage.out

# go cover test variables
PKGS ?= $(shell go list ./... | grep -v /vendor/ | tr '\n' ' ')

# Go env vars
export GO111MODULE=on
export CGO_ENABLED=1

# Verbose output
ifdef VERBOSE
V = -v
endif

all: clean fmt_check test test_with_coverage

# Run tests on all non-vendor directories
.PHONY: test
test: TESTOPTS =
test:
	@echo "+ $@ $(TESTOPTS)"
	@echo
	$(eval TAGS += integration)
	go test $(V) \
		-tags="$(TAGS)" \
		-count=1 \
		--race \
		-covermode=atomic \
		-coverprofile=$(COVEROUT) \
		$(PKGS)

# Check for code well-formedness
fmt_check:
	./ci/format.sh

# Test and generate coverage
test_with_coverage:
	./ci/test.sh

# Clean up everything
.PHONY: clean
clean:
	rm -f *.cov
