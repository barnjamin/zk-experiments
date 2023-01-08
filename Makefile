# ### RISC0 COMMANDS ### #

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


# ### ZOKRATES COMMANDS ### #

ZOKDIR := "groth16/zokrates"

# bls12_377, bls12_381, bn128, bw6_761
CURVE := "bls12_381"

ZOK := "root"
alice: pre-clean-zok
	cd ${ZOKDIR} && ./alice.sh ${CURVE} ${ZOK}

WIT := "337,113569"
eve:
	cd ${ZOKDIR} && ./eve.sh ${ZOK} ${WIT}

root: alice eve

secret-factor: 
	make alice CURVE="bls12_381" ZOK="secret_factor"
	make eve WIT="15825923429238183706" ZOK="secret_factor"

secret-factor2: # not very useful actually
	make alice CURVE="bls12_381" ZOK="secret_factor2"
	make eve ZOK="secret_factor2" WIT="15825923428474158623,15825923429238183706"

# ### ALGORAND BEAKER COMMAND ### #

CONTRACTS_DIR := "groth16/contracts"
run-contract:
	cd ${CONTRACTS_DIR} && python main.py

# ### INTEGRATED COMMAND (AND DEFAULT TARGET) ### #
zk-snarks-and-beaker-it: root secret-factor run-contract

.DEFAULT_GOAL := zk-snarks-and-beaker-it
