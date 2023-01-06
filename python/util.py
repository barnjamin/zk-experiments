from hashlib import sha256
from sha256 import generate_hash

# montgomery form constants
M = int.from_bytes(bytes.fromhex("88000001"), "big")
R2 = 1172168163
PRIME = int(15 * (1 << 27) + 1)


def sha_compress(a: bytes, b: bytes):
    assert (
        len(a) + len(b) == 64
    ), "Cannot use sha_compress directly unless the length of bytes is a multiple of 64"
    return generate_hash(bytearray(list(a) + list(b)), compress_only=True)


def sha_hash(a: bytes) -> bytes:
    return sha256(a).digest()


def u8_to_u32(u8s: list[int]) -> list[int]:
    elems = 4
    u32s = []
    for idx in range(int(len(u8s) / elems)):
        u32s.append(
            int.from_bytes(bytes(u8s[idx * elems : (idx + 1) * elems]), "little")
        )
    return u32s


def u32_to_u8(u32s: list[int]) -> list[int]:
    u8s = []
    for idx in range(len(u32s)):
        u8s.extend(list(u32s[idx].to_bytes(4, "little")))
    return u8s


def to_elem(raw: int):
    return encode_mont(raw % PRIME)


def encode_mont(a: int) -> int:
    return mul(R2, a)


def decode_mont(a: int) -> int:
    return mul(1, a)


def add(lhs: int, rhs: int) -> int:
    x = wrapped_add(lhs, rhs, 32)
    return x if x < PRIME else wrapped_sub(x, PRIME, 32)


def sub(lhs: int, rhs: int) -> int:
    x = wrapped_sub(lhs, rhs, 32)
    return x if x >= PRIME else wrapped_add(x, PRIME, 32)


def mul(lhs: int, rhs: int) -> int:
    o64 = wrapped_mul(lhs, rhs, 64)
    cast_down_o64 = int.from_bytes(o64.to_bytes(8, "big")[4:], "big")
    low = wrapped_sub(0, cast_down_o64, 32)
    red = wrapped_mul(M, low, 32)
    o64 += wrapped_mul(red, PRIME, 64)
    ret = o64 >> 32
    if ret > PRIME:
        return ret - PRIME
    return ret


def wrapped_mul(lhs: int, rhs: int, size: int) -> int:
    return (lhs * rhs) % 2**size


def wrapped_add(lhs: int, rhs: int, size: int) -> int:
    return (lhs + rhs) % 2**size


def wrapped_sub(lhs: int, rhs: int, size: int) -> int:
    return (lhs - rhs) % 2**size
