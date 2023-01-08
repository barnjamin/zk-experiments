from poly_ext import *


class PolyExtStepDef:
    def __init__(self, block: list[PolyExtStep], ret: int):
        self.block = block
        self.ret = ret


def get_def():
    import json

    with open("poly_ext_step_def.json") as f:
        step_def = json.loads(f.read())

    steps: list[PolyExtStep] = [eval(x) for x in step_def["steps"]]
    return PolyExtStepDef(block=steps, ret=step_def["ret"])
