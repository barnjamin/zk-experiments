from base64 import b64decode

from algosdk.encoding import encode_address

from beaker import client, sandbox, consts

from verifier.application import Verifier  # type: ignore
from vscode_hackery import hack_path
from zokrates import parse_proof, parse_verification_key  # type: ignore


INCLUDE_DEPRECATED = False
EVE_TRIES_AGAIN = True


def demo(app_id: int = 0):
    alice = sandbox.get_accounts().pop()
    eve = sandbox.get_accounts().pop()
    algod_client = sandbox.get_algod_client()

    snarky = Verifier(version=9)
    alice_ac = client.ApplicationClient(
        algod_client, snarky, app_id=app_id, signer=alice.signer
    )

    print("# ---- --------------------- ---- #")
    print("# ---- Alice Sets up the App ---- #")
    print("# ---- --------------------- ---- #")

    if app_id == 0:
        app_id, _, _ = alice_ac.create()
        print(f"Created app: {app_id}")
        funding_amount = 1_000_000 * consts.algo
        alice_ac.fund(funding_amount)
        print(f"And funded with: {funding_amount:,} µAlgos")
    else:
        alice_ac.build()
        alice_ac.update()

    boxes = [(0, name.encode()) for name in snarky.boxes_names.values()]

    # Bootstrap with vk
    alice_ac.call(snarky.bootstrap_root, vk=parse_verification_key("root"), boxes=boxes)

    if INCLUDE_DEPRECATED:
        alice_ac.call(
            snarky.bootstrap_secret_factor,
            vk=parse_verification_key("secret_factor"),
            boxes=boxes,
        )

    alice_ac.call(
        snarky.bootstrap_secret_factor2,
        vk=parse_verification_key("secret_factor2"),
        boxes=boxes,
    )

    print("# ---- ------------------------------- ---- #")
    print("# ---- Now for Eve - the bounty hunter ---- #")
    print("# ---- ------------------------------- ---- #")

    eve_ac = client.ApplicationClient(
        algod_client, snarky, app_id=alice_ac.app_id, signer=eve.signer
    )
    eve_ac.build()
    eve_ac.update()

    # Pass proof && inputs to be verified
    r_proof, r_inputs = parse_proof("root")
    r_result = eve_ac.call(
        snarky.verify_root, inputs=r_inputs, proof=r_proof, boxes=boxes
    )
    print(f"Contract verifies root? {r_result.return_value}")

    if INCLUDE_DEPRECATED:
        bounty_hunt(eve_ac, eve, snarky, boxes, deprecated=True)

    bounty_hunt(eve_ac, eve, snarky, boxes, deprecated=False)


def bounty_hunt(eve_ac, eve, verifier, boxes, deprecated=False):
    if deprecated:
        proof_prefix = "secret_factor"
        vf_method = verifier.deprecated_verify_secret_factor
        claim_method = verifier.deprecated_claim_bounty
        SENTINEL = "___deprecated___"
    else:
        proof_prefix = "secret_factor2"
        vf_method = verifier.verify_secret_factor2
        claim_method = verifier.claim_bounty
        SENTINEL = "THE __REAL__ __DEAL__ !!!"

    sf_proof, sf_inputs = parse_proof(proof_prefix)
    sf_result = eve_ac.call(
        vf_method,
        inputs=sf_inputs,
        proof=sf_proof,
        boxes=boxes,
    )
    print(f"Contract verifies secret_factor? {sf_result.return_value}")

    cb_result = eve_ac.call(
        claim_method,
        inputs=sf_inputs,
        proof=sf_proof,
        winner=eve.address,
        boxes=boxes,
    )
    hidden_factor = cb_result.return_value
    print(
        f"Eve claim_bounty? YES!!! Here's the encrypted secret_factor: {hidden_factor:_}"
    )
    expected_eve_address_b64 = cb_result.tx_info["logs"][2]
    expected_eve_address_b32 = encode_address(b64decode(expected_eve_address_b64))
    assert (
        expected_eve_address_b32 == eve.address
    ), f"{expected_eve_address_b32} != {eve.address}"

    pymt_txn = cb_result.tx_info["inner-txns"][-1]["txn"]["txn"]
    rcv_amount = pymt_txn["amt"]
    assert (
        expected_amt := 1337_000_000
    ) == rcv_amount, f"{expected_amt} != {rcv_amount}"

    rcv_address = pymt_txn["rcv"]
    assert (
        expected_eve_address_b32 == rcv_address
    ), f"{expected_eve_address_b32} != {rcv_address}"

    print(
        f"We've sent {rcv_amount:,} µAlgos to address={expected_eve_address_b32} (eve's address={eve.address})"
    )

    if EVE_TRIES_AGAIN:
        print("Suppose Eve is evil and tries to claim the same bounty twice:")
        try:
            cb_result2 = eve_ac.call(
                claim_method,
                inputs=sf_inputs,
                proof=sf_proof,
                winner=eve.address,
                boxes=boxes,
            )
            print(f"Contract claim_bounty again? {cb_result2.return_value}")
        except client.logic_error.LogicException as cle:
            print(f"THANKFULLY Eve COULD NOT claim_bounty again:\n{cle}")

    composite = 1698269078375486647
    secret_summand = 15825923428474158623
    factor = (hidden_factor + 2**64 - secret_summand) % 2**64
    print(
        f"""
{SENTINEL} EX-POST-FACTO VERIFICATION BY ALICE FOR {composite=:_}:
DECRYPT {hidden_factor=:_} --> (x + 2**64 - ({secret_summand=:_}) % 2**64)
    = {factor:_}
{(1 < factor < composite)=:_} (1 < {factor:_} < {composite:_})
{(composite % factor)=:_} ({composite:_} % {factor:_})
{(composite // factor)=:_}
"""
    )


if __name__ == "__main__":
    demo()
    artifacts_dir = hack_path("contracts/artifacts")
    Verifier(version=9).dump(str(artifacts_dir))
