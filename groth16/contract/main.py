import json
import algosdk.abi as sdkabi
from beaker import *
from beaker import client, sandbox

from verifier.bls12_381 import VerificationKey, Proof, Inputs
from verifier.contract import Verifier

vk_codec = sdkabi.ABIType.from_string(str(VerificationKey().type_spec()))
proof_codec = sdkabi.ABIType.from_string(str(Proof().type_spec()))
input_codec = sdkabi.ABIType.from_string("byte[32][1]")

data_path = "../zokrates"


def decode_scalar(v: str) -> bytes:
    return bytes.fromhex(v[2:])


def decode_g1(coords: list[str]) -> bytes:
    x = bytes.fromhex(coords[0][2:])
    y = bytes.fromhex(coords[1][2:])
    return x + y


def decode_g2(coords: list[list[str]]) -> bytes:
    x_0 = bytes.fromhex(coords[0][0][2:])
    x_1 = bytes.fromhex(coords[0][1][2:])
    y_0 = bytes.fromhex(coords[1][0][2:])
    y_1 = bytes.fromhex(coords[1][1][2:])
    return x_0 + x_1 + y_0 + y_1


def get_proof_and_inputs() -> tuple[bytes, bytes]:
    with open(data_path + "/proof.json", "r") as f:
        _proof = json.loads(f.read())

    proof = _proof["proof"]
    a = decode_g1(proof["a"])
    b = decode_g2(proof["b"])
    c = decode_g1(proof["c"])

    inputs = b"".join([decode_scalar(i) for i in _proof["inputs"]])

    return (a + b + c, inputs)


def get_vk() -> bytes:
    with open(data_path + "/verification.key", "r") as f:
        vk = json.loads(f.read())
    alpha = decode_g1(vk["alpha"])
    beta = decode_g2(vk["beta"])
    gamma = decode_g2(vk["gamma"])
    delta = decode_g2(vk["delta"])
    ics = b"".join([decode_g1(ic) for ic in vk["gamma_abc"]])

    return alpha + beta + gamma + delta + ics


app_id = 0
acct = sandbox.get_accounts().pop()
algod_client = sandbox.get_algod_client()

v = Verifier(version=9)
ac = client.ApplicationClient(algod_client, v, app_id=app_id, signer=acct.signer)


def deploy(app_id: int = 0):
    if app_id == 0:
        app_id, _, _ = ac.create()
        print(f"Created app: {app_id}")
        ac.fund(1000 * consts.algo)
    else:
        ac.build()
        ac.update()


def bootstrap():
    ac.call(v.bootstrap, vk=vk_codec.decode(get_vk()), boxes=[(0, "vk")])


def verify():
    proof, inputs = get_proof_and_inputs()
    proof = proof_codec.decode(proof)
    inputs = input_codec.decode(inputs)

    result = ac.call(v.verify, inputs=inputs, proof=proof, boxes=[(0, "vk")])
    print(f"Contract verified? {result.return_value}")


if __name__ == "__main__":
    v.dump("./artifacts")

    deploy()
    bootstrap()
    verify()
