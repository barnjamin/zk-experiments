from beaker import client, sandbox, consts

from verifier.application import Verifier  # type: ignore
from vscode_hackery import hack_path
from zokrates import parse_proof, parse_verification_key  # type: ignore


def demo(app_id: int = 0):
    acct = sandbox.get_accounts().pop()
    algod_client = sandbox.get_algod_client()

    v = Verifier(version=9)
    ac = client.ApplicationClient(algod_client, v, app_id=app_id, signer=acct.signer)

    if app_id == 0:
        app_id, _, _ = ac.create()
        print(f"Created app: {app_id}")
        ac.fund(1000 * consts.algo)
    else:
        ac.build()
        ac.update()

    boxes = [(0, name.encode()) for name in v.boxes_names.values()]

    # Bootstrap with vk
    ac.call(v.bootstrap_root, vk=parse_verification_key("root"), boxes=boxes)
    ac.call(
        v.bootstrap_secret_factor,
        vk=parse_verification_key("secret_factor"),
        boxes=boxes,
    )

    # Pass proof && inputs to be verified
    proof, inputs = parse_proof("root")
    result = ac.call(v.verify_root, inputs=inputs, proof=proof, boxes=boxes)
    print(f"Contract verifies root? {result.return_value}")

    proof, inputs = parse_proof("secret_factor")
    result = ac.call(
        v.deprecated_verify_secret_factor, inputs=inputs, proof=proof, boxes=boxes
    )
    print(f"Contract verifies secret_factor? {result.return_value}")


if __name__ == "__main__":
    demo()
    artifacts_dir = hack_path("contracts/artifacts")
    Verifier(version=9).dump(str(artifacts_dir))
