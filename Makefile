# StarHard developer tasks.  make help
SCRIPTS := StarHard.sh starhard-scan starhard-status starhard-notify tools/embed.sh tools/release.sh tests/checks.sh tests/run-matrix.sh
ENGINE  ?= $(shell command -v podman || command -v docker)

help:
	@echo "make embed    copy starhard-scan/-status/-notify into StarHard.sh (run after editing a helper)"
	@echo "make lint     bash -n + ShellCheck (local shellcheck, else Debian's package in a container)"
	@echo "make test     run tests/checks.sh in a container per distro family (IMAGES='a b' to choose)"
	@echo "make check    embed --check + lint + test   (what CI runs)"
	@echo "make release  dist/ with the scripts, SHA256SUMS and a signature (see tools/release.sh)"

embed:
	tools/embed.sh

lint:
	@for f in $(SCRIPTS); do bash -n $$f || exit 1; done; sh -n tests/in-container.sh
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck -S warning $(SCRIPTS); \
	else $(ENGINE) run --rm -v "$(CURDIR):/src:ro" -w /src docker.io/library/debian:12 sh -c \
	  'apt-get update -qq >/dev/null && apt-get install -y -qq shellcheck >/dev/null 2>&1 && shellcheck -S warning $(SCRIPTS)'; fi
	@echo "lint: ok"

test:
	tests/run-matrix.sh $(IMAGES)

check:
	tools/embed.sh --check
	$(MAKE) lint
	$(MAKE) test

release:
	tools/release.sh

.PHONY: help embed lint test check release
