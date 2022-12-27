from typing import Literal
from pyteal import (
    Len,
    BytesMinus,
    BytesMod,
    Concat,
    Suffix,
    BytesEq,
    Extract,
    If,
    Assert,
    Bytes,
    BytesLt,
    ScratchVar,
    For,
    Subroutine,
    TealType,
    abi,
    Seq,
    Int,
)
from beaker.lib.inline import InlineAssembly

##
# Consts
##

curve = "BLS12_381"
curve_g1 = f"{curve}_G1"
curve_g2 = f"{curve}_G2"

keySize = 48

G1Zero = Bytes((0).to_bytes(keySize * 2, "big"))

PrimeQ = Bytes(
    "base16",
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
)


##
# Types
##

# Always 32 bytes
Scalar = abi.StaticBytes[Literal[32]]
# Depends on keysize (bls == 48, bn254 == 32)
Value = abi.StaticBytes[Literal[48]]

G1 = abi.StaticArray[Value, Literal[2]]
G2 = abi.StaticArray[G1, Literal[2]]

InputNum = Literal[1]
ICNum = Literal[2]  # input num + 1

Inputs = abi.StaticArray[Scalar, InputNum]


class VerificationKey(abi.NamedTuple):
    alpha1: abi.Field[G1]
    beta2: abi.Field[G2]
    gamma2: abi.Field[G2]
    delta2: abi.Field[G2]

    # Can change depending on length of circuit inputs
    IC: abi.Field[abi.StaticArray[G1, ICNum]]


class Proof(abi.NamedTuple):
    A: abi.Field[G1]
    B: abi.Field[G2]
    C: abi.Field[G1]


##
# G1 Ops
##


def x(a):
    return Extract(a, Int(0), Int(keySize))


def y(a):
    return Suffix(a, Int(keySize))


@Subroutine(TealType.bytes)
def add(a: G1, b: G1):
    return curve_add(a.encode(), b.encode())


@Subroutine(TealType.bytes)
def scale(g: G1, factor: Value):
    return curve_scalar_mul(g.encode(), factor.encode())


@Subroutine(TealType.bytes)
def negate(g1):
    return Concat(x(g1), BytesMinus(PrimeQ, BytesMod(y(g1), PrimeQ)))


##
# Lib provided functions
##


@Subroutine(TealType.bytes)
def compute_linear_combination(
    vk: VerificationKey,
    inputs: Inputs,
):
    return Seq(
        (vk_x := abi.make(G1)).decode(G1Zero),
        vk.IC.use(
            lambda ic: Seq(
                vk_x.decode(
                    curve_add(
                        curve_multi_exp(
                            Suffix(ic.encode(), Int(keySize * 2)), inputs.encode()
                        ),
                        Extract(ic.encode(), Int(0), Int(keySize * 2)),
                    )
                ),
            )
        ),
        vk_x.encode(),
    )


@Subroutine(TealType.uint64)
def valid_pairing(proof: Proof, vk: VerificationKey, vk_x: G1):
    g1_buff = ScratchVar()
    g2_buff = ScratchVar()
    return Seq(
        # Construct G1 buffer
        g1_buff.store(
            Concat(
                negate(proof.A.encode()),
                vk.alpha1.encode(),
                vk_x.encode(),
                proof.C.encode(),
            )
        ),
        # Construct G2 buffer
        g2_buff.store(
            Concat(
                proof.B.encode(),
                vk.beta2.encode(),
                vk.gamma2.encode(),
                vk.delta2.encode(),
            )
        ),
        # Check if its a valid pairing
        curve_pairing(g1_buff.load(), g2_buff.load()),
    )


##
# Curve Ops
##


@Subroutine(TealType.uint64)
def curve_subgroup_check_g1(a):
    return InlineAssembly(f"ec_subgroup_check {curve_g1}", a, type=TealType.uint64)


@Subroutine(TealType.uint64)
def curve_subgroup_check_g2(a):
    return InlineAssembly(f"ec_subgroup_check {curve_g2}", a, type=TealType.uint64)


@Subroutine(TealType.bytes)
def curve_add(a, b):
    return InlineAssembly(f"ec_add {curve_g1}", a, b, type=TealType.bytes)


@Subroutine(TealType.bytes)
def curve_multi_exp(a, b):
    return InlineAssembly(f"ec_multi_exp {curve_g1}", a, b, type=TealType.bytes)


@Subroutine(TealType.bytes)
def curve_scalar_mul(a, b):
    return InlineAssembly(f"ec_scalar_mul {curve_g1}", a, b, type=TealType.bytes)


@Subroutine(TealType.uint64)
def curve_pairing(a, b):
    return InlineAssembly(f"ec_pairing_check {curve_g1}", a, b, type=TealType.uint64)
