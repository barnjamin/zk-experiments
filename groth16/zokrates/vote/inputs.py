from random import randbytes
from hashlib import sha256


def as_u32(b: bytes) -> list[int]:
    return [
        int.from_bytes(b[idx * 4 : (idx + 1) * 4], "big", signed=False)
        for idx in range(int(len(b) / 4))
    ]


def as_input(u32s: list[int]) -> str:
    return " ".join([str(b) for b in u32s])


def get_hash(passphrase: list[int]) -> bytes:
    encoded_passphrase = b"".join([x.to_bytes(4, "big") for x in passphrase])
    return sha256(encoded_passphrase).digest()


passphrase_length = 16 * 4

passphrases: list[list[int]] = [
    as_u32(b"deadbeef".zfill(passphrase_length)),
    as_u32(randbytes(passphrase_length)),
]

members = [get_hash(pp) for pp in passphrases]

stuff = f"""
 #!/bin/bash
 
 set -eu
 
 PASSPHRASE="{as_input(passphrases[0])}"
 
 MEMBER_ONE_PHRASE_HASH="{as_input(as_u32(members[0]))}"
 MEMBER_TWO_PHRASE_HASH="{as_input(as_u32(members[1]))}"
 MEMBER_PHRASES="$MEMBER_ONE_PHRASE_HASH $MEMBER_TWO_PHRASE_HASH"
 
 zokrates compute-witness --verbose -a $PASSPHRASE $MEMBER_PHRASES
 
 zokrates generate-proof
 """

with open("generate_proof.sh", "w") as f:
    f.write(stuff)
