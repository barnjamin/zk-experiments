from typing import Literal
from pyteal import (
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
Uint256Zero = Bytes((0).to_bytes(32, "big"))
Uint512Zero = Bytes((0).to_bytes(64, "big"))

PrimeQ = Bytes(
    (
        21888242871839275222246405745257275088696311157297823662689037894645226208583
    ).to_bytes(32, "big")
)
SnarkScalar = Bytes(
    (
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    ).to_bytes(32, "big")
)

##
# Types
##

Uint256 = abi.StaticBytes[Literal[32]]

G1 = abi.StaticArray[Uint256, Literal[2]]
G2 = abi.StaticArray[G1, Literal[2]]

InputNum = Literal[1]
ICNum = Literal[2]  # input num + 1

Inputs = abi.StaticArray[Uint256, InputNum]


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


def x(a: G1):
    return Extract(a.encode(), Int(0), Int(32))


def y(a: G1):
    return Suffix(a.encode(), Int(32))


@Subroutine(TealType.bytes)
def add(a: G1, b: G1):
    return curve_add(a.encode(), b.encode())


@Subroutine(TealType.bytes)
def scale(g: G1, factor: Uint256):
    return curve_scalar_mul(g.encode(), factor.encode())


@Subroutine(TealType.bytes)
def negate(g: G1):
    return (
        If(BytesEq(g.encode(), Uint512Zero))
        .Then(g.encode())
        .Else(Concat(x(g), BytesMinus(PrimeQ, BytesMod(y(g), PrimeQ))))
    )


##
# Lib provided functions
##


@Subroutine(TealType.none)
def assert_proof_points_lt_prime_q(proof: Proof):
    return Seq(
        proof.A.use(
            lambda a: Assert(
                BytesLt(x(a), PrimeQ), BytesLt(y(a), PrimeQ), comment="a point > primeq"
            )
        ),
        proof.B.use(
            lambda b: Seq(
                b[0].use(
                    lambda b_0: Assert(
                        BytesLt(x(b_0), PrimeQ),
                        BytesLt(y(b_0), PrimeQ),
                        comment="b0 point > primeq",
                    )
                ),
                b[1].use(
                    lambda b_1: Assert(
                        BytesLt(x(b_1), PrimeQ),
                        BytesLt(y(b_1), PrimeQ),
                        comment="b1 point > primeq",
                    )
                ),
            )
        ),
        proof.C.use(
            lambda c: Assert(
                BytesLt(x(c), PrimeQ), BytesLt(y(c), PrimeQ), comment="c point > primeq"
            )
        ),
    )


@Subroutine(TealType.bytes)
def compute_linear_combination(
    vk: VerificationKey,
    inputs: Inputs,
):
    # intermediate step
    scaled = abi.make(G1)
    return Seq(
        # init vk_x to 0
        (vk_x := abi.make(G1)).decode(Uint512Zero),
        # TODO: check if len(inputs) == len(vk.ic)+1?
        # Iterate over inputs, accumulating sum
        For(
            (idx := ScratchVar()).store(Int(0)),
            idx.load() < inputs.length(),
            idx.store(idx.load() + Int(1)),
        ).Do(
            # get/check input value
            inputs[idx.load()].store_into((input := abi.make(Uint256))),
            Assert(BytesLt(input.get(), SnarkScalar), comment="input >= snark scalar"),
            # scale circuit value by input
            # vk_x += scaled(vk.ic[idx+1], input[idx])
            vk.IC.use(
                lambda ics: ics[idx.load() + Int(1)].use(
                    lambda vk_ic: scaled.decode(scale(vk_ic, input))
                )
            ),
            # add scaled point to vk_X
            vk_x.decode(add(vk_x, scaled)),
        ),
        # vk_X += vk.IC[0]
        vk.IC.use(lambda ics: ics[Int(0)].use(lambda ic: vk_x.decode(add(vk_x, ic)))),
        vk_x.encode(),
    )


@Subroutine(TealType.uint64)
def valid_pairing(proof: Proof, vk: VerificationKey, vk_x: G1):
    g1_buff = ScratchVar()
    g2_buff = ScratchVar()
    return Seq(
        # Construct G1 buffer
        proof.A.use(lambda a: g1_buff.store(negate(a))),
        vk.alpha1.use(lambda a: g1_buff.store(Concat(g1_buff.load(), a.encode()))),
        g1_buff.store(Concat(g1_buff.load(), vk_x.encode())),
        proof.C.use(lambda c: g1_buff.store(Concat(g1_buff.load(), c.encode()))),
        # Construct G2 buffer
        proof.B.use(lambda b: g2_buff.store(b.encode())),
        vk.beta2.use(lambda b: g2_buff.store(Concat(g2_buff.load(), b.encode()))),
        vk.gamma2.use(lambda g: g2_buff.store(Concat(g2_buff.load(), g.encode()))),
        vk.delta2.use(lambda d: g2_buff.store(Concat(g2_buff.load(), d.encode()))),
        # Check if its a valid pairing
        curve_pairing(g1_buff.load(), g2_buff.load()),
    )


##
# Curve Ops
##

# "ec_add": proto("bb:b")
@Subroutine(TealType.bytes)
def curve_add(a, b):
    return InlineAssembly("ec_add BN254_G1", a, b, type=TealType.bytes)


# "ec_scalar_mul":  proto("bb:b"), costly(970)
@Subroutine(TealType.bytes)
def curve_scalar_mul(a, b):
    return InlineAssembly("ec_scalar_mul BN254_G1", a, b, type=TealType.bytes)


# "ec_pairing":  proto("bb:i"), costly(8700)
@Subroutine(TealType.uint64)
def curve_pairing(a, b):
    return InlineAssembly("ec_pairing_check BN254", a, b, type=TealType.uint64)
