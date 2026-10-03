.PHONY: help build build-arti test check deb deb-arti bump-major bump-minor bump-patch release clean

help:
	@echo 'build | build-arti | test | check | deb | deb-arti | bump-major | bump-minor | bump-patch | release | fuzz-smoke | clean'

build:
	cargo xtask build

build-arti:
	cargo xtask build-arti

test:
	cargo test --locked --workspace

check:
	cargo xtask check

deb:
	cargo xtask deb

deb-arti:
	cargo xtask deb-arti

bump-major:
	cargo xtask bump major

bump-minor:
	cargo xtask bump minor

bump-patch:
	cargo xtask bump patch

release:
	cargo xtask release

clean:
	cargo clean

.PHONY: fuzz-smoke
fuzz-smoke:
	cargo xtask fuzz-smoke
