from fp import Elem, ExtElem, ExtElemOne, ExtElemZero


class MixState:
    def __init__(self, tot: ExtElem, mul: ExtElem):
        self.tot = tot
        self.mul = mul


class PolyExtStep:
    op: str
    args: list[str]
    _args: list[int]

    def __init__(self, op: str, args: list[str]):
        self.op = op
        self.args = args
        self._args = [int(v) for v in args]

    def as_dict(self):
        return {"op": self.op, "args": self.args}

    @staticmethod
    def from_dict(d: dict[str, str | list[str]]) -> "PolyExtStep":
        return PolyExtStep(op=d["op"], args=d["args"])  # type: ignore


class PolyExtStepDef:
    def __init__(self, block: list[PolyExtStep], ret: int):
        self.block = block
        self.ret = ret

    def step(
        self, mix: ExtElem, u: list[ExtElem], args: tuple[list[Elem], list[Elem]]
    ) -> MixState:
        fp_vars: list[ExtElem] = []
        mix_vars: list[MixState] = []

        for idx, op in enumerate(self.block):
            match op.op:
                case "Const":
                    elem = Elem.from_int(op._args[0])
                    fp_vars.append(ExtElem.from_subfield(elem))
                case "Get":
                    get_idx: int = op._args[0]
                    fp_vars.append(u[get_idx])
                case "GetGlobal":
                    base: int = op._args[0]
                    offset: int = op._args[1]
                    fp_vars.append(ExtElem.from_subfield(args[base][offset]))
                case "Add":
                    x1: int = op._args[0]
                    x2: int = op._args[1]
                    fp_vars.append(fp_vars[x1] + fp_vars[x2])
                case "Sub":
                    sub_x1: int = op._args[0]
                    sub_x2: int = op._args[1]
                    fp_vars.append(fp_vars[sub_x1] - fp_vars[sub_x2])
                case "Mul":
                    mul_x1: int = op._args[0]
                    mul_x2: int = op._args[1]
                    fp_vars.append(fp_vars[mul_x1] * fp_vars[mul_x2])
                case "TRUE":
                    mix_vars.append(
                        MixState(
                            tot=ExtElemZero,
                            mul=ExtElemOne,
                        )
                    )
                case "AndEqz":
                    xeq: MixState = mix_vars[op._args[0]]
                    val: ExtElem = fp_vars[op._args[1]]
                    mix_vars.append(
                        MixState(
                            tot=xeq.tot + xeq.mul * val,
                            mul=xeq.mul * mix,
                        )
                    )
                case "AndCond":
                    xcond: MixState = mix_vars[op._args[0]]
                    cond: ExtElem = fp_vars[op._args[1]]
                    inner = mix_vars[op._args[2]]
                    mix_vars.append(
                        MixState(
                            tot=xcond.tot + cond * inner.tot * xcond.mul,
                            mul=xcond.mul * inner.mul,
                        )
                    )
                case _:
                    raise Exception("???")

        assert len(fp_vars) == len(self.block) - (
            self.ret + 1
        ), "Miscalculated capacity for fp_vars"
        assert len(mix_vars) == self.ret + 1, "Miscalculated capacity for mix_vars"

        return mix_vars[self.ret]


def compute_poly(
    u: list[ExtElem], poly_mix: ExtElem, out: list[Elem], mix: list[Elem]
) -> ExtElem:
    poly_step_def = get_def()
    return poly_step_def.step(poly_mix, u, (out, mix)).tot


def get_def() -> PolyExtStepDef:
    import json

    with open("steps.json") as f:
        step_def = json.loads(f.read())

    steps: list[PolyExtStep] = [PolyExtStep.from_dict(x) for x in step_def]
    # TODO: hardcoded `ret`
    return PolyExtStepDef(block=steps, ret=2688)
