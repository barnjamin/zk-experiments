class PolyExtStep:
    def step(self):
        match self:
            case PolyExtStepConst():
                # let elem = F::Elem::from_u64(*value as u64);
                # fp_vars.push(F::ExtElem::from_subfield(&elem));
                pass
            case PolyExtStepGet():
                # fp_vars.push(u[*tap]);
                pass
            case PolyExtStepGetGlobal():
                # fp_vars.push(F::ExtElem::from_subfield(&args[*base][*offset]));
                pass
            case PolyExtStepAdd():
                # fp_vars.push(fp_vars[*x1] + fp_vars[*x2]);
                pass
            case PolyExtStepSub():
                # fp_vars.push(fp_vars[*x1] - fp_vars[*x2]);
                pass
            case PolyExtStepMul():
                # fp_vars.push(fp_vars[*x1] * fp_vars[*x2]);
                pass
            case PolyExtStepTRUE():
                # mix_vars.push(MixState {
                #     tot: F::ExtElem::ZERO,
                #     mul: F::ExtElem::ONE,
                # });
                pass
            case PolyExtStepAndEqz():
                # let x = mix_vars[*x];
                # let val = fp_vars[*val];
                # mix_vars.push(MixState {
                #     tot: x.tot + x.mul * val,
                #     mul: x.mul * *mix,
                # });
                pass
            case PolyExtStepAndCond():
                # let x = mix_vars[*x];
                # let cond = fp_vars[*cond];
                # let inner = mix_vars[*inner];
                # mix_vars.push(MixState {
                #     tot: x.tot + cond * inner.tot * x.mul,
                #     mul: x.mul * inner.mul,
                # });
                pass
            case _:
                raise Exception("???")


class PolyExtStepTRUE(PolyExtStep):
    def __init__(self):
        pass


class PolyExtStepConst(PolyExtStep):
    def __init__(self, v: int):
        self.value = v


class PolyExtStepGet(PolyExtStep):
    def __init__(self, tap: int):
        self.tap = tap


class PolyExtStepGetGlobal(PolyExtStep):
    def __init__(self, base: int, offset: int):
        self.base = base
        self.offset = offset


class PolyExtStepAdd(PolyExtStep):
    def __init__(self, x1: int, x2: int):
        self.x1 = x1
        self.x2 = x2


class PolyExtStepSub(PolyExtStep):
    def __init__(self, x1: int, x2: int):
        self.x1 = x1
        self.x2 = x2


class PolyExtStepMul(PolyExtStep):
    def __init__(self, x1: int, x2: int):
        self.x1 = x1
        self.x2 = x2


class PolyExtStepAndEqz(PolyExtStep):
    def __init__(self, x: int, val: int):
        self.x = x
        self.val = val


class PolyExtStepAndCond(PolyExtStep):
    def __init__(self, x: int, cond: int, iter: int):
        self.x = x
        self.cond = cond
        self.iter = iter
