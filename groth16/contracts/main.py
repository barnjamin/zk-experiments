from base64 import b64decode

from algosdk.encoding import encode_address

from beaker import client, sandbox, consts

from verifier.application import Verifier  # type: ignore
from vscode_hackery import hack_path
from zokrates import parse_proof, parse_verification_key  # type: ignore

EVE_TRIES_AGAIN = True


def demo(app_id: int = 0):
    alice = sandbox.get_accounts().pop()
    eve = sandbox.get_accounts().pop()
    algod_client = sandbox.get_algod_client()

    v = Verifier(version=9)
    alice_ac = client.ApplicationClient(
        algod_client, v, app_id=app_id, signer=alice.signer
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

    boxes = [(0, name.encode()) for name in v.boxes_names.values()]

    # Bootstrap with vk
    alice_ac.call(v.bootstrap_root, vk=parse_verification_key("root"), boxes=boxes)
    alice_ac.call(
        v.bootstrap_secret_factor,
        vk=parse_verification_key("secret_factor"),
        boxes=boxes,
    )

    print("# ---- ------------------------------- ---- #")
    print("# ---- Now for Eve - the bounty hunter ---- #")
    print("# ---- ------------------------------- ---- #")

    eve_ac = client.ApplicationClient(
        algod_client, v, app_id=alice_ac.app_id, signer=eve.signer
    )
    eve_ac.build()
    eve_ac.update()

    # Pass proof && inputs to be verified
    r_proof, r_inputs = parse_proof("root")
    r_result = eve_ac.call(v.verify_root, inputs=r_inputs, proof=r_proof, boxes=boxes)
    print(f"Contract verifies root? {r_result.return_value}")

    sf_proof, sf_inputs = parse_proof("secret_factor")
    sf_result = eve_ac.call(
        v.deprecated_verify_secret_factor, inputs=sf_inputs, proof=sf_proof, boxes=boxes
    )
    print(f"Contract verifies secret_factor? {sf_result.return_value}")

    cb_result = eve_ac.call(
        v.claim_bounty,
        inputs=sf_inputs,
        proof=sf_proof,
        winner=eve.address,
        boxes=boxes,
    )
    print(
        f"Eve claim_bounty? YES!!! Here's the encrypted secret_factor: {cb_result.return_value}"
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
                v.claim_bounty,
                inputs=sf_inputs,
                proof=sf_proof,
                winner=eve.address,
                boxes=boxes,
            )
            print(f"Contract claim_bounty again? {cb_result2.return_value}")
        except client.logic_error.LogicException as cle:
            print(f"THANKFULLY Eve COULD NOT claim_bounty again:\n{cle}")
        except Exception as e:
            x = 42


if __name__ == "__main__":
    demo()
    artifacts_dir = hack_path("contracts/artifacts")
    Verifier(version=9).dump(str(artifacts_dir))
