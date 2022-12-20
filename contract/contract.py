from pyteal import *
from beaker import *

class Verifier(Application):
    pass

if __name__ == "__main__":
    Verifier().dump("./artifacts")