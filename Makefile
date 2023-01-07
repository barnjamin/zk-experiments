rust-setup:
	rustup update "nightly"
	rustup default "nightly"

step-minus-1:
	xattr target
	xattr -d com.apple.metadata:com_apple_backup_excludeItem target

step0:
	cargo clean

step1:
	cargo build
	
step2:
	cargo run --bin starter # to produce files

step3:
	cargo run --bin sanitycheck 

pre-clean-zok:
	cd groth16/zokrates && ./clean.sh || exit 0


ZOKDIR := "groth16/zokrates"

# bls12_377, bls12_381, bn128, bw6_761
# CURVE := "bls12_381"
CURVE := "bn128"

# ZOK := "root"
ZOK := "secret_factor"
alice: pre-clean-zok
	cd ${ZOKDIR} && ./alice.sh ${CURVE} ${ZOK}.zok

WIT := "15825923429238183706"
# WIT := "337 113569"
eve:
	cd ${ZOKDIR} && ./eve.sh ${WIT}

alice-and-eve: alice eve

run-contract:
	cd groth16/contracts && python main.py