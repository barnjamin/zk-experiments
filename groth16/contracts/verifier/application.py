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

BUDGET = 17_056


class Verifier(bkr.Application):
    boxes_names = {
        "root": "root_vk",
        "secret_factor": "secret_factor_vk",
        "secret_factor2": "secret_factor2_vk",
    }
    root_vk_box_name = pt.Bytes(boxes_names["root"])
    secret_factor_vk_box_name = pt.Bytes(boxes_names["secret_factor"])
    secret_factor2_vk_box_name = pt.Bytes(boxes_names["secret_factor2"])

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

    @bkr.external(authorize=bkr.Authorize.only(pt.Global.creator_address()))
    def bootstrap_secret_factor2(self, vk: VerificationKey):
        # write the VK to box storage
        return pt.BoxPut(self.secret_factor2_vk_box_name, vk.encode())

    @bkr.external
    def verify_root(self, inputs: Inputs, proof: Proof, *, output: pt.abi.Bool):
        return self._verify(
            inputs, proof, output=output, vk_from_box_method=self.root_vk_from_box
        )

    def _verify(self, inputs, proof, output, vk_from_box_method) -> pt.Expr:
        return pt.Seq(
            self.opup.ensure_budget(pt.Int(BUDGET)),
            # Fetch the VK from box storage
            vk_from_box_method(output=(vk := VerificationKey())),  # type: ignore
            # Compute vk_x from sum of inputs
            (vk_x := pt.abi.make(G1)).decode(compute_linear_combination(vk, inputs)),
            # return result (normal programs should assert out if its invalid)
            output.set(valid_pairing(proof, vk, vk_x)),
        )

    @bkr.external
    def deprecated_claim_bounty(
        self,
        inputs: Inputs,
        proof: Proof,
        winner: pt.abi.Account,
        *,
        output: pt.abi.Uint64,
    ):
        return self._claim_bounty_impl(inputs, proof, winner, output, "secret_factor")

    @bkr.external
    def claim_bounty(
        self,
        inputs: Inputs,
        proof: Proof,
        winner: pt.abi.Account,
        *,
        output: pt.abi.Uint64,
    ):
        return self._claim_bounty_impl(inputs, proof, winner, output, "secret_factor2")

    def _claim_bounty_impl(self, inputs, proof, winner, output, for_what):
        """
        Provide the proof containing the encrypted secret_factor.
        If verification succeeds:
        1. replace the "secret_factor" box value (formerly the verification key) with the encrypted secret_factor
        2. return the encrypted secret_factor
        """
        if for_what == "secret_factor":
            box_name = self.secret_factor_vk_box_name
            box_method = self.secret_factor_vk_from_box
        elif for_what == "secret_factor2":
            box_name = self.secret_factor2_vk_box_name
            box_method = self.secret_factor2_vk_from_box
        else:
            raise AssertionError(f"we don't know what to do with {for_what=}")

        verified = pt.abi.make(pt.abi.Bool)
        box_inputs = pt.abi.make(Inputs)
        return pt.Seq(
            self.assert_verification_key(box_name),  # type: ignore
            self._verify(
                inputs,
                proof,
                output=verified,
                vk_from_box_method=box_method,
            ),
            pt.Assert(
                verified.get(), comment="verification failed!!! (bounty reward refused)"
            ),
            pt.Assert(
                pt.App.box_delete(box_name),
                comment=f"DELETING {for_what} verification box <{self.boxes_names[for_what]}> failed",
            ),
            pt.App.box_put(box_name, inputs.encode()),
            input_box := pt.App.box_get(box_name),
            pt.Assert(
                input_box.hasValue(),
                comment=f"{for_what} box was supposed to have the {for_what} but doesn't exist",
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
        return self._verify(
            inputs,
            proof,
            output=output,
            vk_from_box_method=self.secret_factor_vk_from_box,
        )

    @bkr.external
    def verify_secret_factor2(
        self, inputs: Inputs, proof: Proof, *, output: pt.abi.Bool
    ):
        return self._verify(
            inputs,
            proof,
            output=output,
            vk_from_box_method=self.secret_factor2_vk_from_box,
        )

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
    def secret_factor2_vk_from_box(self, *, output: VerificationKey):
        # Read in the VK from our box
        return pt.Seq(
            vk_data := pt.BoxGet(self.secret_factor2_vk_box_name),
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
