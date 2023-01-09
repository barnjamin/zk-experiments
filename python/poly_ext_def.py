from poly_ext import PolyExtStep


class PolyExtStepDef:
    def __init__(self, block: list[PolyExtStep], ret: int):
        self.block = block
        self.ret = ret


def get_def() -> PolyExtStepDef:
    import json

    with open("steps.json") as f:
        step_def = json.loads(f.read())

    steps: list[PolyExtStep] = [PolyExtStep.from_dict(x) for x in step_def]
    # TODO: hardcoded ret
    return PolyExtStepDef(block=steps, ret=2688)


if __name__ == "__main__":
    print(get_def())
