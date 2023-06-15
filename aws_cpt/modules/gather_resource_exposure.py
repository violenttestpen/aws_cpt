#!/usr/bin/env python3

import json
import sys
from collections import defaultdict
from pathlib import Path

from rich.console import Console, Group
from rich.tree import Tree

from aws_cpt.iam_structs import glob_match, in_glob
from aws_cpt.modules import create_new_argparser
from aws_cpt.modules.gather_who_has import parse_permissions

rsrc_exposure_perms = (
    # Resource Policies
    "logs:PutResourcePolicy",
    "ecr:SetRepositoryPolicy",
    "elasticfilesystem:PutFileSystemPolicy",
    "es:CreateElasticsearchDomain",
    "es:UpdateElasticsearchDomainConfig",
    "glacier:SetVaultAccessPolicy",
    "lambda:AddPermission",
    "lambda:AddLayerVersionPermission",
    "iam:UpdateAssumeRolePolicy",
    "kms:PutKeyPolicy",
    "s3:PutBucketAcl",
    "s3:PutBucketPolicy",
    "secretsmanager:PutResourcePolicy",
    "sns:AddPermission",
    "sqs:AddPermission",
    "ses:PutIdentityPolicy",
    # Sharing APIs
    "ec2:ModifyImageAttribute",
    "ec2:ModifySnapshotAttribute",
    "rds:ModifyDBSnapshot",
)


def main(args):
    input_io = Path(args.input).open("rb") if args.input else sys.stdin.buffer
    output_io = Path(args.output).open("w") if args.output else sys.stdout

    data = json.load(input_io)
    input_io.close()

    root = Tree(f"Roles with Resource Exposure Permissions:")
    for i, action in {0: "Allow", 1: "Deny"}.items():
        action_node = None
        for role, perms in parse_permissions(data, args.verbose):
            if not perms[i]:
                continue

            selected_perms = {
                perm: rsrc
                for perm, rsrc in perms[i].items()
                if in_glob(rsrc_exposure_perms, perm)
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
                    reverse_keys = {}
                    reverse_nodes = defaultdict(list)
                    for rsrc_exposure_perm in rsrc_exposure_perms:
                        if glob_match(perm, rsrc_exposure_perm):
                            if args.reverse:
                                rsrc_str = str(sorted(rsrc))
                                reverse_keys[rsrc_str] = Group(*rsrc)
                                reverse_nodes[rsrc_str].append(rsrc_exposure_perm)
                            else:
                                perm_node = role_node.add(rsrc_exposure_perm)
                                perm_node.add(Group(*rsrc))

                    for rsrc_str, perms in reverse_nodes.items():
                        rsrc_grp = reverse_keys[rsrc_str]
                        perm_node = role_node.add("Resource:").add(rsrc_grp)
                        perm_node.add(Group(*perms))

    Console(file=output_io).print(root)


if __name__ == "__main__":
    parser = create_new_argparser()
    parser.add_argument(
        "--reverse",
        "-r",
        default=False,
        action="store_true",
        help="Show actions grouped by resources instead",
    )
    args = parser.parse_args()

    main(args)
