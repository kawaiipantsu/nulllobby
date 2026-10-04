.PHONY: help build build-arti test check deb deb-arti screenshots bump-major bump-minor bump-patch release release-signed release-unsigned sign-release verify-release ca-status ca-enroll apt-status apt-publish apt-verify clean

help:
	@echo 'build | build-arti | test | check | deb | deb-arti | screenshots | bump-major | bump-minor | bump-patch | release | release-signed | release-unsigned | sign-release | verify-release | ca-status | ca-enroll | apt-status | apt-publish | apt-verify | fuzz-smoke | clean'

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

release-signed:
	cargo xtask release-signed

release-unsigned:
	cargo xtask release-unsigned

sign-release:
	cargo xtask sign-release

verify-release:
	cargo xtask verify-release

ca-status:
	cargo xtask ca-status

ca-enroll:
	cargo xtask ca-enroll

apt-status:
	cargo xtask apt-status

apt-publish:
	cargo xtask apt-publish

apt-verify:
	cargo xtask apt-verify

clean:
	cargo clean

screenshots:
	cargo xtask screenshots

.PHONY: fuzz-smoke
fuzz-smoke:
	cargo xtask fuzz-smoke
