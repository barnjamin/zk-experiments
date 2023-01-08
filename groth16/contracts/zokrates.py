import json
import algosdk.abi as sdkabi  # type: ignore

from typing import Any

from vscode_hackery import hack_path

from verifier.lib.bls12_381 import VerificationKey, Proof  # type: ignore

# TODO: return the actual types from these methods instead of Any

vk_codec = sdkabi.ABIType.from_string(str(VerificationKey().type_spec()))
proof_codec = sdkabi.ABIType.from_string(str(Proof().type_spec()))

# this probably depends very much on the particular *.zok file!
input_codec = sdkabi.ABIType.from_string("byte[32][1]")

data_path = hack_path("zokrates")


def decode_scalar(v: str) -> bytes:
    return bytes.fromhex(v[2:])


def decode_g1(coords: list[str]) -> bytes:
    # TODO: assert expected lengths
    x = bytes.fromhex(coords[0][2:])
    y = bytes.fromhex(coords[1][2:])
    return x + y


def decode_g2(coords: list[list[str]]) -> bytes:
    # TODO: assert expected lengths
    # Z asks: Is G2 a quaternian image?
    x_0 = bytes.fromhex(coords[0][0][2:])
    x_1 = bytes.fromhex(coords[0][1][2:])
    y_0 = bytes.fromhex(coords[1][0][2:])
    y_1 = bytes.fromhex(coords[1][1][2:])
    return x_0 + x_1 + y_0 + y_1


def parse_proof(prefix: str) -> tuple[Any, Any]:
    with open(data_path / f"{prefix}_proof.json", "r") as f:
        _proof = json.loads(f.read())

    proof = _proof["proof"]
    a = decode_g1(proof["a"])
    b = decode_g2(proof["b"])
    c = decode_g1(proof["c"])

    inputs = b"".join([decode_scalar(i) for i in _proof["inputs"]])

    return proof_codec.decode(a + b + c), input_codec.decode(inputs)


def parse_verification_key(prefix: str) -> Any:
    with open(data_path / f"{prefix}_verification.key", "r") as f:
        vk = json.loads(f.read())
    alpha = decode_g1(vk["alpha"])
    beta = decode_g2(vk["beta"])
    gamma = decode_g2(vk["gamma"])
    delta = decode_g2(vk["delta"])
    ics = b"".join([decode_g1(ic) for ic in vk["gamma_abc"]])

    return vk_codec.decode(alpha + beta + gamma + delta + ics)
