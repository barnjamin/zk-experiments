from beaker import client, sandbox, consts

from verifier import Verifier  # type: ignore
from zokrates import get_proof_and_inputs, get_vk  # type: ignore


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
    ac.call(v.bootstrap_root, vk=get_vk("root"), boxes=boxes)
    ac.call(v.bootstrap_secret_factor, vk=get_vk("secret_factor"), boxes=boxes)

    # Pass proof && inputs to be verified
    proof, inputs = get_proof_and_inputs("root")
    result = ac.call(v.verify_root, inputs=inputs, proof=proof, boxes=boxes)
    print(f"Contract verifies root? {result.return_value}")


if __name__ == "__main__":
    demo()

    Verifier(version=9).dump("./artifacts")
