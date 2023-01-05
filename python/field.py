import galois  # type: ignore

# montgomery form constants
M = int.from_bytes(bytes.fromhex("88000001"), "big")
R2 = 1172168163

PRIME = int(15 * (1 << 27) + 1)
Field = galois.GF(PRIME)

G32 = galois.GF(2**32)
G64 = galois.GF(2**64)


def to_elem(raw: int):
    return encode_mont(raw % Field.order)


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
