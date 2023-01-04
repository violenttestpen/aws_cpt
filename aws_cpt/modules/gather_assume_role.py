#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict
from itertools import chain
from pathlib import Path
from typing import Any, List, Tuple

from aws_cpt.iam_structs import IAMDocument, Policy, Role


def parse_iam(data: object) -> Tuple[List[Role], List[Policy]]:
    iam_document = IAMDocument(**data)
    return iam_document.RoleDetailList, iam_document.Policies


def extract_trust_policy(data: object):
    roles, _ = parse_iam(data)
    statements = defaultdict(dict)

    for r in roles:
        for assume_role_stmt in r.AssumeRolePolicyDocument.Statement:
            for principal in assume_role_stmt.Principal:
                stmt = statements[principal.Name]
                stmt["Type"] = principal.Type
                actions = stmt.get("Actions", defaultdict(dict))
                for action in assume_role_stmt.Action:
                    resources = actions[assume_role_stmt.Effect].get(action, [])
                    resources.append(r.Arn)
                    actions[assume_role_stmt.Effect][action] = resources
                stmt["Actions"] = actions
                stmt["Condition"] = assume_role_stmt.Condition

    return {k: statements[k] for k in sorted(statements.keys())}


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
            allowed_rsrcs = stmt["Actions"].get("Allow", {})
            for rsrcs in allowed_rsrcs.values():
                table_data[stmt["Type"]].append(
                    (principal, rsrcs, stmt.get("Condition"))
                )

        try:
            from rich.console import Console, Group
            from rich.table import Table
            from rich.tree import Tree

            console = Console(file=output_io)
            root = Tree("AssumeRole Policy Tree")

            for principal_type, principal_pairs in table_data.items():
                tree_type = root.add(principal_type)
                for principal, rsrcs, conditions in principal_pairs:
                    rsrc_grp = tree_type.add(principal).add(Group(*rsrcs))
                    if conditions:
                        for k, v in conditions.items():
                            rsrc_grp.add(f"Condition: {k} = {v}")

            console.print(root)
        except ImportError:
            for principal_type, principal_pairs in table_data.items():
                output_io.write(principal_type + "\n")
                output_io.write("=" * len(principal_type) + "\n")
                for principal, rsrcs, conditions in principal_pairs:
                    output_io.write(f"- {principal}\n")
                    output_io.write("\n".join(f"  \_ {r}" for r in rsrcs) + "\n")
                    if conditions:
                        for k, v in conditions.items():
                            output_io.write(f"    \_ Condition: {k} = {v}\n")
                    output_io.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        "-i",
        help="The filepath to the output of `iam get-account-authorization-details`",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="The filepath to save the results",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        default=False,
        action="store_true",
        help="Verbose mode",
    )
    args = parser.parse_args()

    main(args)
