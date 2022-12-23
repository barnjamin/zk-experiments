import pyteal as pt
import beaker as bkr

from .lib import (
    Inputs,
    Proof,
    VerificationKey,
    G1,
    compute_linear_combination,
    valid_pairing,
    assert_proof_points_lt_prime_q,
)


class Verifier(bkr.Application):
    _vk_box_name = "vk"
    vk_box_name = pt.Bytes(_vk_box_name)

    opup = pt.OpUp(pt.OpUpMode.OnCall)

    @bkr.update(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def update(self):
        return pt.Approve()

    @bkr.external(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def bootstrap(self, vk: VerificationKey):
        # write the VK to box storage
        return pt.BoxPut(self.vk_box_name, vk.encode())

    @bkr.external
    def verify(self, inputs: Inputs, proof: Proof, *, output: pt.abi.Bool):
        return pt.Seq(
            # idk if this will need to change but its enough for now
            self.opup.ensure_budget(pt.Int(1350)),
            # Fetch the VK from box storage
            self.get_vk(output=(vk := VerificationKey())),  # type: ignore
            # Compute vk_x from sum of inputs
            (vk_x := pt.abi.make(G1)).decode(compute_linear_combination(vk, inputs)),
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
    Verifier(version=9).dump("../artifacts")
