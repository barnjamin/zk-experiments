import pyteal as pt
import beaker as bkr

from lib import (
    CircuitInputs,
    Proof,
    VerificationKey,
    G1,
    compute_linear_combination,
    valid_pairing,
    check_proof_values,
)


class Verifier(bkr.Application):
    _vk_box_name = "vk"
    vk_box_name = pt.Bytes(_vk_box_name)

    @bkr.external(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def bootstrap(self, vk: VerificationKey):
        return pt.BoxPut(self.vk_box_name, vk.encode())

    @bkr.external
    def verify(self, inputs: CircuitInputs, proof: Proof, *, output: pt.abi.Bool):
        return pt.Seq(
            # Make sure proof doesnt have any values > primeQ
            pt.Assert(
                check_proof_values(proof), comment="A value in the proof was > PrimeQ"
            ),
            self.get_vk(output=(vk := VerificationKey())),
            # Compute vk_x from inputs
            (vk_x := G1())._set_with_computed_type(compute_linear_combination(vk, inputs)),  # type: ignore
            # return result (normal programs should assert out if its invalid)
            output.set(valid_pairing(proof, vk, vk_x)),
        )

    @bkr.internal
    def get_vk(self, *, output: VerificationKey):
        # Read in the VK from our box
        return pt.Seq(
            vk_data := pt.BoxGet(self.vk_box_name),
            pt.Assert(vk_data.hasValue(), comment="Verification Key not set"),
            output.decode(vk_data.value()),
        )


if __name__ == "__main__":
    Verifier().dump("./artifacts")
