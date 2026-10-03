.PHONY: help build test check deb bump-major bump-minor bump-patch release clean

help:
	@echo 'build | test | check | deb | bump-major | bump-minor | bump-patch | release | clean'

build:
	cargo xtask build

test:
	cargo test --locked --workspace

check:
	cargo xtask check

deb:
	cargo xtask deb

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
