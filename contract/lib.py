from typing import Literal
from pyteal import (
    BytesMinus,
    BytesMod,
    Concat,
    Replace,
    Suffix,
    BytesEq,
    If,
    Assert,
    Bytes,
    BytesLt,
    ScratchVar,
    For,
    Subroutine,
    TealType,
    abi,
    ABIReturnSubroutine,
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
Uint512 = abi.StaticBytes[Literal[64]]

CircuitInputs = abi.DynamicArray[Uint256]

G1 = abi.StaticArray[Uint256, Literal[2]]
G2 = abi.StaticArray[G1, Literal[2]]


class VerificationKey(abi.NamedTuple):
    alpha1: abi.Field[G1]
    beta2: abi.Field[G2]
    gamma2: abi.Field[G2]
    delta2: abi.Field[G2]

    # Can change depending on length of circuit inputs
    IC: abi.Field[abi.StaticArray[G1, Literal[2]]]


class Proof(abi.NamedTuple):
    A: abi.Field[G1]
    B: abi.Field[G2]
    C: abi.Field[G1]


##
# G1 Ops
##


@Subroutine(TealType.bytes)
def add(a: G1, b: G1):
    return curve_add(a.encode(), b.encode())


@Subroutine(TealType.bytes)
def scale(g: G1, factor: Uint256):
    return curve_scalar_mul(g.encode(), factor.encode())


@Subroutine(TealType.bytes)
def negate(g: G1):
    return Seq(
        (raw_bytes := ScratchVar()).store(g.encode()),
        If(
            BytesEq(raw_bytes.load(), Uint512Zero),
            raw_bytes.load(),
            Replace(
                raw_bytes.load(),
                Int(32),
                BytesMinus(PrimeQ, BytesMod(Suffix(raw_bytes.load(), Int(32)), PrimeQ)),
            ),
        ),
    )


##
# Lib provided functions
##
@Subroutine(TealType.uint64)
def check_proof_values(proof: Proof):
    ## TODO:  actually implement this
    # proof.A.use(
    #    lambda g1: g1.x.use(lambda x: pt.Assert(pt.BytesLt(x.get(), PrimeQ)))
    # ),
    return Int(1)


@ABIReturnSubroutine
def compute_linear_combination(
    vk: VerificationKey, inputs: CircuitInputs, *, output: G1
):
    # alias output to vk_x
    scaled = abi.make(G1)
    vk_x = output
    return Seq(
        vk_x.decode(Uint512Zero),
        For(
            (idx := ScratchVar()).store(Int(0)),
            idx.load() < inputs.length(),
            idx.store(idx.load() + Int(1)),
        ).Do(
            inputs[idx.load()].store_into((pt := abi.make(Uint256))),
            Assert(BytesLt(pt.get(), SnarkScalar), comment="verifier gte snark scalar"),
            # vk_x += scaled(vk.ic[idx+1], input[idx])
            vk.IC.use(
                lambda ics: ics[idx.load() + Int(1)].use(
                    lambda vk_ic: scaled.decode(scale(vk_ic, pt))
                )
            ),
            vk_x.decode(add(vk_x, scaled)),
        ),
        # vk_X += vk.IC[0]
        vk.IC.use(lambda ics: ics[Int(0)].use(lambda ic: vk_x.decode(add(vk_x, ic)))),
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
    return InlineAssembly("ec_add", a, b, type=TealType.bytes)


# "ec_scalar_mul":  proto("bb:b"), costly(970)
@Subroutine(TealType.bytes)
def curve_scalar_mul(a, b):
    return InlineAssembly("ec_scalar_mul", a, b, type=TealType.bytes)


# "ec_pairing":  proto("bb:i"), costly(8700)
@Subroutine(TealType.uint64)
def curve_pairing(a, b):
    return InlineAssembly("ec_pairing", a, b, type=TealType.uint64)


# {0xe0, "ec_add", opEcAdd, proto("bb:b"), pairingVersion,
#     costByField("v", &EcCurves, []int{
#         BN254_G1: 10, BN254_G2: 10,
#         BLS12_381_G1: 20, BLS12_381_G2: 20})},
# {0xe1, "ec_scalar_mul", opEcScalarMul, proto("bb:b"), pairingVersion,
#     costByField("v", &EcCurves, []int{
#         BN254_G1: 100, BN254_G2: 100,
#         BLS12_381_G1: 200, BLS12_381_G2: 200})},
# {0xe2, "ec_pairing", opEcPairingCheck, proto("bb:i"), pairingVersion,
#     costByField("v", &EcCurves, []int{BN254: 1000, BLS12_381: 2000})},
