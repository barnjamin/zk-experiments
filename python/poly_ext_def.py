from poly_ext import PolyExtStep, MixState
from fp import ExtElem, Elem


class PolyExtStepDef:
    def __init__(self, block: list[PolyExtStep], ret: int):
        self.block = block
        self.ret = ret

    def step(
        self, mix: ExtElem, u: list[ExtElem], args: tuple[list[Elem], list[Elem]]
    ) -> MixState:
        fp_vars: list[ExtElem] = []
        mix_vars: list[MixState] = []

        for op in self.block:
            op.step(fp_vars, mix_vars, mix, u, args)

        assert len(fp_vars) == len(self.block) - (
            self.ret + 1
        ), "Miscalculated capacity for fp_vars"
        assert len(mix_vars) == self.ret + 1, "Miscalculated capacity for mix_vars"

        return mix_vars[self.ret]


def get_def() -> PolyExtStepDef:
    import json

    with open("steps.json") as f:
        step_def = json.loads(f.read())

    steps: list[PolyExtStep] = [PolyExtStep.from_dict(x) for x in step_def]
    # TODO: hardcoded ret
    return PolyExtStepDef(block=steps, ret=2688)


if __name__ == "__main__":
    print(get_def())
