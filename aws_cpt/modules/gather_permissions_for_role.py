#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict
from itertools import chain
from pathlib import Path
from typing import Any, List, Tuple

from aws_cpt.iam_structs import IAMDocument, Policy, PolicyStatement, Role
from aws_cpt.modules import create_new_argparser


def parse_iam(data: object) -> Tuple[List[Role], List[Policy]]:
    iam_document = IAMDocument(**data)
    return iam_document.RoleDetailList, iam_document.Policies


def process_iam_actions(statements, verbose=False, reverse=False):
    overall_perms = defaultdict(lambda: defaultdict(set))
    for perm in statements:
        if not isinstance(perm, PolicyStatement):
            print("Error processing:", perm)
            continue

        not_resource = (f"~{nr}" for nr in perm.NotResource)
        k, v = perm.Action, [*chain(perm.Resource, not_resource)]

        if condition := perm.Condition:
            v = (f"{r} (Condition: {condition})" for r in v)

        for key in k:
            overall_perms[perm.Effect][key] |= set(v)

    # Process both all effects (Allow, Deny)
    for effect, permissions in overall_perms.items():
        perms = {k: sorted(v) if len(v) > 1 else [*v] for k, v in permissions.items()}

        if not verbose:
            # Fast case for AdministratorAccess
            if perms.get("*") == ["*"]:
                overall_perms[effect] = {"*": "*"}
                continue

            # Identify service wildcards
            service_wildcards = [
                action.partition(":")[0]
                for action, rsrcs in perms.items()
                if action.endswith(":*") and rsrcs == ["*"]
            ]

            # Strip ARN of resource for brevity, and subsume service wildcards
            perms = {
                action: [
                    rsrc if rsrc.startswith("*") else ":".join(rsrc.split(":")[5:])
                    for rsrc in rsrcs
                ]
                for action, rsrcs in perms.items()
                if action.partition(":")[0] not in service_wildcards
            }

            # Subsume resource wildcard
            perms = {
                action: ["*"] if "*" in rsrcs else rsrcs
                for action, rsrcs in perms.items()
            }

            # Collapse resource list if there's only 1 resource
            perms = {
                action: rsrc[0] if len(rsrc) == 1 else rsrc
                for action, rsrc in perms.items()
            }

            for svc in service_wildcards:
                perms.update({f"{svc}:*": "*"})

        overall_perms[effect] = {k: perms[k] for k in sorted(perms)}

    if reverse:
        reverse_perms = defaultdict(lambda: defaultdict(set))

        for effect, perms in overall_perms.items():
            for k, v in perms.items():
                for new_k in v if isinstance(v, list) else [v]:
                    reverse_perms[effect][new_k].add(k)

        overall_perms = {
            effect: {k: sorted(v) for k, v in reverse_perms[effect].items()}
            for effect in reverse_perms
        }

    return overall_perms["Allow"], overall_perms["Deny"]


def extract_permissions(role_name: str, data: Any, verbose=False, reverse=False):
    roles, policies = parse_iam(data)

    if not any(role_candidates := [r for r in roles if r.RoleName == role_name]):
        return {}, {}

    (role,) = role_candidates
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
    return process_iam_actions(statements, verbose, reverse)


def main(args: List[str]):
    input_io = Path(args.input).open("rb") if args.input else sys.stdin.buffer
    output_io = Path(args.output).open("w") if args.output else sys.stdout

    data = json.load(input_io)
    allow_perms, deny_perms = extract_permissions(
        args.role, data, args.verbose, args.reverse
    )
    input_io.close()

    if allow_perms:
        output_io.write("Allow:\n")
        output_io.write(json.dumps(allow_perms, indent=4))

    if deny_perms:
        output_io.write("\n\n")
        output_io.write("Deny:\n")
        output_io.write(json.dumps(deny_perms, indent=4))


if __name__ == "__main__":
    parser = create_new_argparser()
    parser.add_argument(
        "--reverse",
        "-r",
        default=False,
        action="store_true",
        help="Show actions grouped by resources instead",
    )
    parser.add_argument("role", help="Roles that are in scope")
    args = parser.parse_args()

    main(args)
