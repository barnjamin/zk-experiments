from beaker import *
from beaker import client, sandbox

from contract import Verifier


def main():

    accts = sandbox.get_accounts()
    acct = accts.pop()

    algod_client = sandbox.get_algod_client()

    v = Verifier(version=9)
    ac = client.ApplicationClient(algod_client, v, signer=acct.signer)
    app_id, _, _ = ac.create()
    print(f"App id: {app_id}")
    ac.fund(1000 * consts.algo)

    #ac.call(v.bootstrap, vk=b"")
    #result = ac.call(v.verify, inputs=b"", proof=b"")

    #print(result.return_value)


if __name__ == "__main__":
    main()
