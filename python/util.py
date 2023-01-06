from hashlib import sha256
from sha256 import generate_hash, IV
from consts import PRIME, R2, M

import struct


def sha_compress(a: bytes, b: bytes):
    assert (
        len(a) + len(b) == 64
    ), "Cannot use sha_compress directly unless the length of bytes is a multiple of 64"
    return generate_hash(bytearray(list(a) + list(b)), compress_only=True)


def sha_hash(a: bytes) -> bytes:
    return sha256(a).digest()


def hash_raw_pod(raw: list[int]) -> bytes:
    u8s = u32_to_u8(raw)
    chunk_size = 64  # 64 byte chunks

    # little endian u32s
    # Iter 0 'State: [1914189627, 1935612854, 4183361634, 859907526, 2960161666, 1235396345, 2224743624, 1210959022],
    # Block: [18, 1, 70, 24, 135, 2, 146, 0, 155, 131, 6, 37, 182, 153, 142, 35, ...

    # Iter 1 'State: [879058070, 1941735893, 1209893642, 3181760915, 1079618972, 81921200, 4120098236, 146853299],
    # Block: [16, 39, 72, 17, 163, 79, 203, 61, 105, 140, 97, 29, 223, 236, 199, ...

    state: list[int] = IV
    for idx in range(int(len(u8s) / chunk_size)):
        block = u8s[idx * chunk_size : (idx + 1) * chunk_size]

        state = u8_to_u32(
            list(
                generate_hash(bytearray(block), initial_state=state, compress_only=True)
            )
        )

        print("idx: {} state: {} block: {}".format(idx, swap_endian(state), block))

        if idx == 1:
            break

    if state is None:
        raise Exception("wat")

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
