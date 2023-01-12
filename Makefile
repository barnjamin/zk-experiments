python-setup:
	pip install -r requirements.txt 

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

root: CURVE = "bls12_381" # bls12_377, bls12_381, bn128, bw6_761
root: ZOK = "root"
root: WIT = '["337", "113569"]'

# NOT SECURE!!!!
secret-factor: CURVE = "bls12_381"
secret-factor: ZOK = "secret_factor"
secret-factor: WIT = '["15825923429238183706"]'

secret-factor2: CURVE = "bls12_381" 
secret-factor2: ZOK = "secret_factor2" 
secret-factor2: WIT = '["15825923429238183706", "15825923428474158623"]'

alice:
	cd ${ZOKDIR} && ./alice.sh ${CURVE} ${ZOK}

eve:
	cd ${ZOKDIR} && ./eve.sh ${ZOK} ${WIT}

dapp-simulate:
	cd ${ZOKDIR} && ./dApp_simulate.sh ${ZOK}

root secret-factor secret-factor2: alice eve dapp-simulate

actors:
	make root
	make secret-factor
	make secret-factor2

zok-all: pre-clean-zok actors

# ### ALGORAND BEAKER COMMAND ### #

CONTRACTS_DIR := "groth16/contracts"
run-contract:
	cd ${CONTRACTS_DIR} && python main.py

# ### INTEGRATED COMMAND (AND DEFAULT TARGET) ### #
zk-snarks-and-beaker-it: zok-all run-contract

.DEFAULT_GOAL := zk-snarks-and-beaker-it
