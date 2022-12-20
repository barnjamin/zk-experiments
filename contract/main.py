from beaker import *
from beaker import client, sandbox

from contract import Verifier


def main():

    accts = sandbox.get_accounts()
    acct = accts.pop()

    algod_client = sandbox.get_algod_client()

    v = Verifier(version=9)
    ac = client.ApplicationClient(algod_client, v, signer=acct.signer)
    ac.create()
    ac.fund(1000 * consts.algo)

    result = ac.call(v.bootstrap, vk=b"")
    print(result.return_value)


if __name__ == "__main__":
    main()
