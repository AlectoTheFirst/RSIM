"""Writes the records that Python textfsm gives for each test input.

usage: python -I expected.py <fixture dir> <template dir> [<template dir> ...]

Each input is <fixture dir>/<group>/<case>.txt. The template is
<group>/template.textfsm when it exists, else <group>.textfsm in the first
template dir that has it. The result goes to <case>.json next to the input:
the header and the records, the header and the message of a parse error, or
the message of a template error.
"""

import json
import sys
from pathlib import Path

import textfsm


def main() -> None:
    root = Path(sys.argv[1])
    dirs = [Path(d) for d in sys.argv[2:]]
    for case in sorted(root.glob("*/*.txt")):
        local = case.parent / "template.textfsm"
        name = case.parent.name + ".textfsm"
        if local.is_file():
            template = local
        else:
            template = next(d / name for d in dirs if (d / name).is_file())
        out = {"template": template.name}
        try:
            with template.open() as handle:
                fsm = textfsm.TextFSM(handle)
        except textfsm.TextFSMTemplateError as error:
            out["template_error"] = str(error)
        else:
            out["header"] = fsm.header
            try:
                out["records"] = fsm.ParseText(case.read_bytes().decode("utf-8"))
            except textfsm.TextFSMError as error:
                out["error"] = str(error)
        case.with_suffix(".json").write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()
