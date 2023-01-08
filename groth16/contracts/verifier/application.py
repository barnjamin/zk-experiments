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

    @bkr.external
    def claim_bounty(
        self,
        inputs: Inputs,
        proof: Proof,
        winner: pt.abi.Account,
        *,
        output: pt.abi.Uint64,
    ):
        """
        Provide the proof containing the encrypted secret_factor.
        If verification succeeds:
        1. replace the "secret_factor" box value (formerly the verification key) with the encrypted secret_factor
        2. return the encrypted secret_factor
        """
        verified = pt.abi.make(pt.abi.Bool)
        box_inputs = pt.abi.make(Inputs)
        return pt.Seq(
            self.assert_verification_key(box_name := self.secret_factor_vk_box_name),  # type: ignore
            self._verify_secret_factor(inputs, proof, output=verified),
            pt.Assert(
                verified.get(), comment="verification failed!!! (bounty reward refused)"
            ),
            pt.Assert(
                pt.App.box_delete(box_name),
                comment=f"DELETING secret_factor verification box <{self.boxes_names['secret_factor']}> failed",
            ),
            pt.App.box_put(box_name, inputs.encode()),
            input_box := pt.App.box_get(box_name),
            pt.Assert(
                input_box.hasValue(),
                comment="secret_factor box was supposed to have the secret_factor but doesn't exist",
            ),
            box_inputs.decode(input_box.value()),
            pt.Log(pt.Bytes("abc123")),
            pt.Log(pt.Bytes("Sending 1337 algos to Eve with address in the next log:")),
            pt.Log(winner.address()),
            pt.InnerTxnBuilder.Execute(
                {
                    pt.TxnField.type_enum: pt.TxnType.Payment,
                    pt.TxnField.amount: pt.Int(1337_000_000),
                    pt.TxnField.receiver: winner.address(),
                }
            ),
            output.set(pt.Btoi(pt.Suffix(box_inputs[0].encode(), pt.Int(24)))),
        )

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

    @bkr.internal
    def assert_verification_key(self, box_name):
        return pt.Seq(
            box_maybe := pt.App.box_get(box_name),
            pt.Assert(box_maybe.hasValue(), comment=f"box <{box_name}> doesn't exist"),
            pt.Assert(
                pt.Len(box_maybe.value()) > pt.Int(32),
                comment=f"box <{box_name}> is too short to be a verification key. Previously verified?",
            ),
        )


if __name__ == "__main__":
    Verifier(version=9).dump("../artifacts")
