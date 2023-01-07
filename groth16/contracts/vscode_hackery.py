from pathlib import Path

# hackery to deal with vs-code debugging issues:
def hack_path(dir_name: str, parent: str = "groth16") -> Path:
    cwd = Path.cwd()
    if cwd.name == "zk-experiments":
        cwd = cwd / parent
    else:
        cwd = cwd.parent
    return cwd / dir_name
