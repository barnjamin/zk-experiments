import pyteal as pt
import beaker as bkr

from .lib.bls12_381 import (
    Inputs,
    Proof,
    VerificationKey,
    G1,
    compute_linear_combination,
    valid_pairing,
)


class Verifier(bkr.Application):
    boxes_names = {
        "root": "root_vk",
        "secret_factor": "secret_factor_vk",
    }
    root_vk_box_name = pt.Bytes(boxes_names["root"])
    secret_factor_vk_box_name = pt.Bytes(boxes_names["secret_factor"])

    opup = pt.OpUp(pt.OpUpMode.OnCall)

    @bkr.update(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def update(self):
        return pt.Approve()

    @bkr.external(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def bootstrap_root(self, vk: VerificationKey):
        # write the VK to box storage
        return pt.BoxPut(self.root_vk_box_name, vk.encode())

    @bkr.external(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def bootstrap_secret_factor(self, vk: VerificationKey):
        # write the VK to box storage
        return pt.BoxPut(self.secret_factor_vk_box_name, vk.encode())

    @bkr.external
    def verify_root(self, inputs: Inputs, proof: Proof, *, output: pt.abi.Bool):
        return pt.Seq(
            # idk if this will need to change but its enough for now
            self.opup.ensure_budget(pt.Int(13500)),
            # Fetch the VK from box storage
            self.root_vk_from_box(output=(vk := VerificationKey())),  # type: ignore
            # Compute vk_x from sum of inputs
            (vk_x := pt.abi.make(G1)).decode(compute_linear_combination(vk, inputs)),
            # return result (normal programs should assert out if its invalid)
            output.set(valid_pairing(proof, vk, vk_x)),
        )

    def _verify_secret_factor(self, inputs, proof, output) -> pt.Expr:
        return pt.Seq(
            # idk if this will need to change but its enough for now
            # Z: yeah, looks like GTG for groth 16
            self.opup.ensure_budget(pt.Int(13500)),
            # Fetch the VK from box storage
            self.secret_factor_vk_from_box(output=(vk := VerificationKey())),  # type: ignore
            # Compute vk_x from sum of inputs
            (vk_x := pt.abi.make(G1)).decode(compute_linear_combination(vk, inputs)),
            # return result (normal programs should assert out if its invalid)
            output.set(valid_pairing(proof, vk, vk_x)),
        )

    # @bkr.external
    # def claim_bounty(self, inputs: Inputs, proof: Proof, *, output: pt.abi.Bool):
    #     verification = pt.abi.make(pt.abi.Bool)
    #     verify_seq = self._verify_secret_factor(inputs, proof, verification)
    #     return pt.Seq(
    #         pt.Assert(
    #             verify_seq, comment="verification failed!!! (bounty reward refused)"
    #         )
    #     )

    @bkr.external
    def deprecated_verify_secret_factor(
        self, inputs: Inputs, proof: Proof, *, output: pt.abi.Bool
    ):
        return self._verify_secret_factor(inputs, proof, output)

    @bkr.internal
    def root_vk_from_box(self, *, output: VerificationKey):
        # Read in the VK from our box
        return pt.Seq(
            vk_data := pt.BoxGet(self.root_vk_box_name),
            pt.Assert(vk_data.hasValue(), comment="Verification Key not set"),
            output.decode(vk_data.value()),
        )

    @bkr.internal
    def secret_factor_vk_from_box(self, *, output: VerificationKey):
        # Read in the VK from our box
        return pt.Seq(
            vk_data := pt.BoxGet(self.secret_factor_vk_box_name),
            pt.Assert(vk_data.hasValue(), comment="Verification Key not set"),
            output.decode(vk_data.value()),
        )


if __name__ == "__main__":
    Verifier(version=9).dump("../artifacts")