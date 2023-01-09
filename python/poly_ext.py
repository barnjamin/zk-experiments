from util import to_elem
from fp import Elem, ExtElem, ExtElemOne, ExtElemZero


def stoi(s) -> int:
    return int(s)


def ext_elem_from_sub_field(e: Elem) -> ExtElem:
    return ExtElem([e, Elem(0), Elem(0), Elem(0)])


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
        self._args = [stoi(v) for v in args]

    def as_dict(self):
        return {"op": self.op, "args": self.args}

    @staticmethod
    def from_dict(d: dict[str, str | list[str]]) -> "PolyExtStep":
        return PolyExtStep(op=d["op"], args=d["args"])  # type: ignore

    def step(
        self,
        fp_vars: list[ExtElem],
        mix_vars: list[MixState],
        mix: ExtElem,
        u: list[ExtElem],
        args: tuple[list[Elem], list[Elem]],
    ):
        match self.op:
            case "Const":
                elem = Elem(to_elem(self._args[0]))
                fp_vars.append(ext_elem_from_sub_field(elem))
            case "Get":
                fp_vars.append(u[self._args[0]])
            case "GetGlobal":
                base: int = self._args[0]
                offset: int = self._args[1]
                fp_vars.append(ext_elem_from_sub_field(args[base][offset]))
                pass
            case "Add":
                x1: int = self._args[0]
                x2: int = self._args[1]
                fp_vars.append(fp_vars[x1] + fp_vars[x2])
                pass
            case "Sub":
                sub_x1: int = self._args[0]
                sub_x2: int = self._args[1]
                fp_vars.append(fp_vars[sub_x1] - fp_vars[sub_x2])
                pass
            case "Mul":
                mul_x1: int = self._args[0]
                mul_x2: int = self._args[1]
                fp_vars.append(fp_vars[mul_x1] * fp_vars[mul_x2])
                pass
            case "TRUE":
                mix_vars.append(
                    MixState(
                        tot=ExtElemZero,
                        mul=ExtElemOne,
                    )
                )
            case "AndEqz":
                xeq: MixState = mix_vars[self._args[0]]
                val: ExtElem = fp_vars[self._args[1]]
                mix_vars.append(
                    MixState(
                        tot=xeq.tot + xeq.mul * val,
                        mul=xeq.mul * mix,
                    )
                )
                pass
            case "AndCond":
                xcond: MixState = mix_vars[self._args[0]]
                cond: ExtElem = fp_vars[self._args[1]]
                inner = mix_vars[self._args[2]]
                mix_vars.append(
                    MixState(
                        tot=xcond.tot + cond * inner.tot * xcond.mul,
                        mul=xcond.mul * inner.mul,
                    )
                )
                pass
            case _:
                raise Exception("???")
