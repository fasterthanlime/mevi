# Just manual: https://github.com/casey/just

_default:
	just --list

install:
	cargo install --path crates/mevi

serve:
	trunk serve --release crates/mevi-frontend/index.html