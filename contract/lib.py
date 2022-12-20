from typing import Literal
from pyteal import (
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


@ABIReturnSubroutine
def add(a: G1, b: G1, *, output: G1):
    return output.decode(curve_add(a.encode(), b.encode()))


@ABIReturnSubroutine
def scale(g: G1, factor: Uint256, *, output: G1):
    return output.decode(
        curve_scalar_mul(g.encode(), factor.encode())
    )


@ABIReturnSubroutine
def negate(g: G1, *, output: G1):
    return Seq(
        (raw_bytes := ScratchVar()).store(g.encode()),
        If(
            BytesEq(raw_bytes.load(), Uint512Zero),
            output.decode(g.encode()),
            output.decode(
                Replace(
                    raw_bytes.load(),
                    Int(32),
                    PrimeQ - (Suffix(raw_bytes.load(), Int(32)) % PrimeQ),
                )
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
                    lambda vk_ic: scaled._set_with_computed_type(scale(vk_ic, pt)) # type: ignore
                )  
            ),
            vk_x._set_with_computed_type(add(vk_x, scaled)) # type: ignore
        ),
        # vk_X += vk.IC[0]
        vk.IC.use(
            lambda ics: ics[Int(0)].use(
                lambda ic: vk_x._set_with_computed_type(add(vk_x, ic))  # type: ignore
            )
        ),
    )


#                      a1,      a2,       b1,       b2,    c1,       c2,      d1,        d2
# Pairing.negate(proof.A), proof.B, vk.alfa1, vk.beta2, vk_x, vk.gamma2, proof.C, vk.delta2


@Subroutine(TealType.uint64)
def valid_pairing(proof: Proof, vk: VerificationKey, vk_x: G1):
    return Seq(
        (g1_buff := ScratchVar()).store(Bytes("")),
        (g2_buff := ScratchVar()).store(Bytes("")),
        # Combine all the G1 points
        # Combine all the G2 points
        Int(1)
    )


#        G1Point[4] memory p1 = [a1, b1, c1, d1];
#        G2Point[4] memory p2 = [a2, b2, c2, d2];

#        uint256 inputSize = 24;

#        uint256[] memory input = new uint256[](inputSize);

#        for (uint256 i = 0; i < 4; i++) {
#            uint256 j = i * 6;
#            input[j + 0] = p1[i].X;
#            input[j + 1] = p1[i].Y;
#            input[j + 2] = p2[i].X[0];
#            input[j + 3] = p2[i].X[1];
#            input[j + 4] = p2[i].Y[0];
#            input[j + 5] = p2[i].Y[1];
#        }

#        success := staticcall(
#           sub(gas(), 2000),
#           8,
#           add(input, 0x20),
#           mul(inputSize, 0x20),
#           out,
#           0x20
#        )


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
