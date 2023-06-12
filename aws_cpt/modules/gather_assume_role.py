#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict
from itertools import chain
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rich.console import Console, Group
from rich.tree import Tree

from aws_cpt.iam_structs import IAMDocument, Policy, Role
from aws_cpt.modules import create_new_argparser


def parse_iam(data: object) -> Tuple[List[Role], List[Policy]]:
    iam_document = IAMDocument(**data)
    return iam_document.RoleDetailList, iam_document.Policies


def extract_trust_policy(data: object) -> Dict[str, dict]:
    roles, _ = parse_iam(data)
    statements = defaultdict(dict)

    for r in roles:
        for assume_role_stmt in r.AssumeRolePolicyDocument.Statement:
            for principal in assume_role_stmt.Principal:
                stmt = statements[principal.Name]
                stmt["Type"] = principal.Type
                stmt["Condition"] = assume_role_stmt.Condition

                actions = stmt.get("Actions", defaultdict(lambda: defaultdict(list)))
                for action in assume_role_stmt.Action:
                    actions[assume_role_stmt.Effect][action].append(r.Arn)
                stmt["Actions"] = actions

    return {k: statements[k] for k in sorted(statements)}


def main(args: List[str]):
    input_io = Path(args.input).open("rb") if args.input else sys.stdin.buffer
    output_io = Path(args.output).open("w") if args.output else sys.stdout

    data = json.load(input_io)
    input_io.close()

    statements = extract_trust_policy(data)

    if args.verbose:
        output_io.write(json.dumps(statements, indent=4))
    else:
        table_data = defaultdict(list)
        for principal, stmt in statements.items():
            for rsrcs in stmt["Actions"].get("Allow", {}).values():
                table_data[stmt["Type"]].append(
                    (principal, rsrcs, stmt.get("Condition"))
                )

        root = Tree("AssumeRole Policy Tree")

        for principal_type, principal_pairs in table_data.items():
            tree_type = root.add(principal_type)
            for principal, rsrcs, conditions in principal_pairs:
                rsrc_grp = tree_type.add(principal).add(Group(*rsrcs))
                if conditions:
                    for k, v in conditions.items():
                        rsrc_grp.add(f"Condition: {k} = {v}")

        Console(file=output_io).print(root)


if __name__ == "__main__":
    parser = create_new_argparser()
    args = parser.parse_args()

    main(args)
