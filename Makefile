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

ZOK := "root"
WIT := "337 113569"
pre-contract-zok: pre-clean-zok
	cd groth16/zokrates && ./doit.sh ${ZOK}.zok ${WIT}

run-contract:
	cd groth16/contracts && python main.py