from beaker import *
from beaker import client, sandbox

from contract import Verifier


def main(app_id: int = 0):

    accts = sandbox.get_accounts()
    acct = accts.pop()

    algod_client = sandbox.get_algod_client()

    v = Verifier(version=9)
    ac = client.ApplicationClient(algod_client, v, app_id=app_id, signer=acct.signer)
    if app_id == 0:
        app_id, _, _ = ac.create()
        ac.fund(1000 * consts.algo)
    else:
        ac.build()
        ac.update()

    print(f"App id: {app_id}")

    # ac.call(v.bootstrap, vk=b"")
    # result = ac.call(v.verify, inputs=b"", proof=b"")

    # print(result.return_value)


if __name__ == "__main__":
    main(1416)
