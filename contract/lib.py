from typing import Literal
from pyteal import (
    And,
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
    BytesZero,
)
from beaker.lib.inline import InlineAssembly

Zero = Bytes((0).to_bytes(32, "big"))

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

Uint256 = abi.StaticBytes[Literal[32]]

CircuitInputs = abi.DynamicArray[Uint256]


class G1(abi.NamedTuple):
    x: abi.Field[Uint256]
    y: abi.Field[Uint256]


class G2(abi.NamedTuple):
    x: abi.Field[abi.StaticArray[Uint256, Literal[2]]]
    y: abi.Field[abi.StaticArray[Uint256, Literal[2]]]


class VerificationKey(abi.NamedTuple):
    alpha1: abi.Field[G1]
    beta2: abi.Field[G2]
    gamma2: abi.Field[G2]
    delta2: abi.Field[G2]
    IC: abi.Field[abi.StaticArray[G1, Literal[2]]]


class Proof(abi.NamedTuple):
    A: abi.Field[G1]
    B: abi.Field[G2]
    C: abi.Field[G1]


@Subroutine(TealType.uint64)
def check_proof_values(proof: Proof):
    ## TODO: rest of them
    # proof.A.use(
    #    lambda g1: g1.x.use(lambda x: pt.Assert(pt.BytesLt(x.get(), PrimeQ)))
    # ),
    return Seq(Int(1))


@ABIReturnSubroutine
def compute_linear_combination(
    vk: VerificationKey, inputs: CircuitInputs, *, output: G1
):
    scaled = G1()
    ic0 = G1()
    vk_x = output
    return Seq(
        (x := abi.make(Uint256)).set(BytesZero(Int(32))),
        (y := abi.make(Uint256)).set(BytesZero(Int(32))),
        vk_x.set(x, y),
        For(
            (idx := ScratchVar()).store(Int(0)),
            idx.load() < inputs.length(),
            idx.store(idx.load() + Int(1)),
        ).Do(
            inputs[idx.load()].store_into((pt := abi.make(Uint256))),
            Assert(BytesLt(pt.get(), SnarkScalar), comment="verifier gte snark scalar"),
            # computes: scaled = VK.IC[idx+1] * inputs[idx]
            vk.IC.use(
                lambda ics: ics[idx.load() + Int(1)].use(
                    lambda ic: inputs[idx.load()].use(
                        lambda i: scaled._set_with_computed_type(
                            scale(ic, i)  # type: ignore
                        )
                    )
                )
            ),
            # new_vk_x = old_vkx + scaled
            vk_x._set_with_computed_type(add(vk_x, scaled)),  # type: ignore
        ),
        # vk_X + vk.IC[0]
        vk.IC.use(lambda ics: ics[Int(0)].store_into(ic0)),
        vk_x._set_with_computed_type(add(vk_x, ic0)),  # type: ignore
    )


@Subroutine(TealType.uint64)
def valid_pairing(proof: Proof, vk: VerificationKey, vk_x: G1):
    a1 = G1()
    return Seq(
        # a1._set_with_computed_type(proof.A.use(lambda a: negate(a, output=a1)), # type: ignore
        Int(1)
    )


# Pairing.pairing( Pairing.negate(proof.A), proof.B, vk.alfa1, vk.beta2, vk_x, vk.gamma2, proof.C, vk.delta2 );
#        G1Point memory a1,
#        G2Point memory a2,
#        G1Point memory b1,
#        G2Point memory b2,
#        G1Point memory c1,
#        G2Point memory c2,
#        G1Point memory d1,
#        G2Point memory d2

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

# "bn256_add": proto("bb:b"), costly(70)
@Subroutine(TealType.bytes)
def curve_add(a, b):
    return InlineAssembly("bn256_add", a, b, type=TealType.bytes)


# "bn256_scalar_mul":  proto("bb:b"), costly(970)
@Subroutine(TealType.bytes)
def curve_scalar_mul(a, b):
    return InlineAssembly("bn256_scalar_mul", a, b, type=TealType.bytes)


# "bn256_pairing":  proto("bb:i"), costly(8700)
@Subroutine(TealType.uint64)
def curve_pairing(a, b):
    return InlineAssembly("bn256_pairing", a, b, type=TealType.uint64)


@ABIReturnSubroutine
def add(a: G1, b: G1, *, output: G1):
    x = abi.make(Uint256)
    y = abi.make(Uint256)
    return Seq(
        a.x.use(lambda ax: b.x.use(lambda bx: x.set(curve_add(ax.get(), bx.get())))),
        a.y.use(lambda ay: b.y.use(lambda by: y.set(curve_add(ay.get(), by.get())))),
        output.set(x, y),
    )


@ABIReturnSubroutine
def negate(g: G1, *, output: G1):
    return Seq(
        g.x.use(
            lambda gx: g.y.use(
                lambda gy: If(
                    And(BytesEq(gx.get(), Zero), BytesEq(gy.get(), Zero)),
                    output.decode(g.encode()),
                    Seq(
                        (newy := abi.make(Uint256)).set(PrimeQ - (gy.get() % PrimeQ)),
                        output.set(gx, newy),
                    ),
                )
            )
        )
    )


@ABIReturnSubroutine
def scale(g: G1, factor: Uint256, *, output: G1):
    x = abi.make(Uint256)
    y = abi.make(Uint256)
    return Seq(
        g.x.use(lambda gx: x.set(curve_scalar_mul(gx.get(), factor.get()))),
        g.y.use(lambda gy: y.set(curve_scalar_mul(gy.get(), factor.get()))),
        output.set(x, y),
    )
