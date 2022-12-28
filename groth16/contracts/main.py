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

    ac.call(v.bootstrap, vk=get_vk(), boxes=[(0, b"vk")])

    proof, inputs = get_proof_and_inputs()
    result = ac.call(v.verify, inputs=inputs, proof=proof, boxes=[(0, b"vk")])
    print(f"Contract verified? {result.return_value}")


if __name__ == "__main__":
    demo()

    Verifier(version=9).dump("./artifacts")
