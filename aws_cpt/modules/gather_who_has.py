#!/usr/bin/env python3

import json
import sys
from itertools import chain
from pathlib import Path
from typing import Any, List

from rich.console import Console, Group
from rich.tree import Tree

from aws_cpt.iam_structs import in_glob
from aws_cpt.modules import create_new_argparser, gather_permissions_for_role


def parse_permissions(data: Any, verbose=False):
    roles, policies = gather_permissions_for_role.parse_iam(data)

    for role in roles:
        attached_policies_arns = [p["PolicyArn"] for p in role.AttachedManagedPolicies]
        attached_policies = (p for p in policies if p.Arn in attached_policies_arns)

        attached_policies_docs = (
            p.Document
            for sp in attached_policies
            for p in sp.PolicyVersionList
            if p.IsDefaultVersion
        )
        attached_policies_stmt = (p.Statement for p in attached_policies_docs)

        inline_policies_stmt = (
            s for p in role.RolePolicyList for s in p.PolicyDocument.Statement
        )

        statements = chain(*attached_policies_stmt, inline_policies_stmt)
        yield role, gather_permissions_for_role.process_iam_actions(statements, verbose)


def main(args: List[str]):
    input_io = Path(args.input).open("rb") if args.input else sys.stdin.buffer
    output_io = Path(args.output).open("w") if args.output else sys.stdout

    data = json.load(input_io)
    input_io.close()

    root = Tree(f"Roles with any of Permissions: ({', '.join(args.permission)})")
    for i, action in {0: "Allow", 1: "Deny"}.items():
        action_node = None
        for role, perms in parse_permissions(data, args.verbose):
            if not perms[i]:
                continue

            selected_perms = {
                perm: rsrc
                for perm, rsrc in perms[i].items()
                if in_glob(args.permission, perm)
            }

            role_node = None
            for perm, rsrc in selected_perms.items():
                if action_node is None:
                    action_node = root.add(action)

                if role_node is None:
                    role_node = action_node.add(
                        f"{role.RoleName} ({', '.join(selected_perms.keys())})"
                    )

                if args.verbose:
                    perm_node = role_node.add(perm)
                    perm_node.add("Resource:").add(Group(*rsrc))

    Console(file=output_io).print(root)


if __name__ == "__main__":
    parser = create_new_argparser()
    parser.add_argument(
        "permission", nargs="+", help="Filter using specified permission(s)"
    )
    args = parser.parse_args()

    main(args)
