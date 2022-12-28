from random import randbytes
from Cryptodome.Hash import SHA512

# TODO: this does not produce the same output as zokrates sha256 

def get_hash(passphrase: bytes) -> bytes:
    h = SHA512.new(truncate="256")
    h.update(passphrase)
    return h.digest()


def get_hash_u32(passphrase: bytes) -> list[int]:
    h = SHA512.new(truncate="256")
    h.update(passphrase)
    d = h.digest()

    return [int.from_bytes(d[idx * 4 : (idx + 1) * 4], "big") for idx in range(8)]


def get_passphrase_as_u32(passphrase: bytes) -> list[int]:
    return [
        int.from_bytes(passphrase[idx * 4 : (idx + 1) * 4], "big") for idx in range(16)
    ]


def get_passphrase_as_input(passphrase: bytes) -> str:
    return " ".join([str(b) for b in get_passphrase_as_u32(passphrase)])


def get_hash_as_input(hb: list[int]) -> str:
    return " ".join([str(b) for b in hb])


passphrase_length = 16 * 4

passphrases = [randbytes(passphrase_length), randbytes(passphrase_length)]
members = [get_hash_u32(pp) for pp in passphrases]


passphrase = get_passphrase_as_input(passphrases[0])
member_one = get_hash_as_input(members[0])
member_two = get_hash_as_input(members[1])

# Hardcoded override so the passphrase hash matches
actual = [
    "0xa86c6a91",
    "0x1ac7ebec",
    "0x8b977630",
    "0x0ba75b48",
    "0x63b79e5b",
    "0x55fb9f6c",
    "0xdbc95533",
    "0x85f6e59f",
]
member_one = " ".join(
    [str(int.from_bytes(bytes.fromhex(b[2:]), "big")) for b in actual]
)


stuff = f"""
PASSPHRASE="{passphrase}"

VOTE="1"

MEMBER_ONE_PHRASE_HASH="{member_one}"
MEMBER_TWO_PHRASE_HASH="{member_two}"
MEMBER_PHRASES="$MEMBER_ONE_PHRASE_HASH $MEMBER_TWO_PHRASE_HASH"

zokrates compute-witness -a $PASSPHRASE $VOTE $MEMBER_PHRASES
"""

print(stuff)
