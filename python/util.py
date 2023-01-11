from hashlib import sha256
from sha256 import generate_hash, IV
from consts import PRIME, R2, M

import struct


def sha_compress_leaves(a: bytes, b: bytes):
    assert (
        len(a) + len(b) == 64
    ), "Cannot use sha_compress directly unless the length of bytes is a multiple of 64"
    return generate_hash(bytearray(list(a) + list(b)), compress_only=True)


def sha_hash(a: bytes) -> bytes:
    return sha256(a).digest()


def hash_raw_data(raw: list[int]) -> bytes:
    u8s = u32_to_u8(raw)
    chunk_size = 64  # 64 byte chunks
    state: list[int] = IV
    for idx in range(int(len(u8s) / chunk_size)):
        block = u8s[idx * chunk_size : (idx + 1) * chunk_size]
        state = u8_to_u32(
            list(
                generate_hash(bytearray(block), initial_state=state, compress_only=True)
            )
        )
        state = swap_endian(state)

    lookback = len(u8s) % chunk_size
    if lookback > 0:
        remainder = u8s[-lookback:]
        block = [0] * 64
        block[: len(remainder)] = remainder[:]
        state = u8_to_u32(
            list(
                generate_hash(bytearray(block), initial_state=state, compress_only=True)
            )
        )
    else:
        # otherwise swap it back
        state = swap_endian(state)

    return bytes(u32_to_u8(state))


def swap_endian(l: list[int]) -> list[int]:
    return [swap32(x) for x in l]


def swap32(i: int):
    return struct.unpack("<I", struct.pack(">I", i))[0]


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


def to_elem(raw: int) -> int:
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
    return x if x < PRIME else wrapped_add(x, PRIME, 32)


def mul(lhs: int, rhs: int) -> int:
    o64 = wrapped_mul(lhs, rhs, 64)
    cast_down_o64 = int.from_bytes(o64.to_bytes(8, "big")[4:], "big")
    low = wrapped_sub(0, cast_down_o64, 32)
    red = wrapped_mul(M, low, 32)
    o64 += wrapped_mul(red, PRIME, 64)
    return (o64 >> 32) % PRIME


def pow(base: int, exp: int) -> int:
    n = exp
    tot = 1
    x = base
    while n != 0:
        if n % 2 == 1:
            tot = mul(tot, x)
        n = n // 2
        x = mul(x, x)
    return tot


def wrapped_mul(lhs: int, rhs: int, size: int) -> int:
    return (lhs * rhs) % 2**size


def wrapped_add(lhs: int, rhs: int, size: int) -> int:
    return (lhs + rhs) % 2**size


def wrapped_sub(lhs: int, rhs: int, size: int) -> int:
    return (lhs - rhs) % 2**size


def wrapped_pow(base: int, exp: int) -> int:
    b = 1
    for _ in range(exp):
        b = wrapped_mul(b, base, 32)
    return b


MAX_ROU_PO2 = 27
ROU_FWD = [
    to_elem(x)
    for x in [
        1,
        2013265920,
        284861408,
        1801542727,
        567209306,
        740045640,
        918899846,
        1881002012,
        1453957774,
        65325759,
        1538055801,
        515192888,
        483885487,
        157393079,
        1695124103,
        2005211659,
        1540072241,
        88064245,
        1542985445,
        1269900459,
        1461624142,
        825701067,
        682402162,
        1311873874,
        1164520853,
        352275361,
        18769,
        137,
    ]
]

ROU_REV = [
    to_elem(x)
    for x in [
        1,
        2013265920,
        1728404513,
        1592366214,
        196396260,
        1253260071,
        72041623,
        1091445674,
        145223211,
        1446820157,
        1030796471,
        2010749425,
        1827366325,
        1239938613,
        246299276,
        596347512,
        1893145354,
        246074437,
        1525739923,
        1194341128,
        1463599021,
        704606912,
        95395244,
        15672543,
        647517488,
        584175179,
        137728885,
        749463956,
    ]
]
