#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from typing import IO, List

from aws_cpt.iam_structs import glob_match, in_glob
from aws_cpt.modules.gather_assume_role import extract_trust_policy
from aws_cpt.modules.gather_permissions_for_role import extract_permissions

privesc_checks = [
    {"perms": ("*",)},
    {"perms": ("sts:AssumeRole",)},
    {"perms": ("iam:CreatePolicyVersion",)},
    {"perms": ("iam:SetDefaultPolicyVersion2",)},
    {
        "perms": ("iam:PassRole", "ec2:RunInstances"),
        "trusted_principal": "ec2.amazonaws.com",
    },
    {
        "perms": ("iam:PassRole", "ec2:RequestSpotInstances"),
        "trusted_principal": "ec2.amazonaws.com",
    },
    {
        "perms": ("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
        "trusted_principal": "ecs.amazonaws.com",
    },
    {
        "perms": ("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:StartTask"),
        "trusted_principal": "ecs.amazonaws.com",
    },
    {"perms": ("iam:CreateAccessKey",)},
    {"perms": ("iam:CreateLoginProfile",)},
    {"perms": ("iam:UpdateLoginProfile",)},
    {"perms": ("iam:AttachUserPolicy",)},
    {"perms": ("iam:AttachGroupPolicy",)},
    {"perms": ("iam:AttachRolePolicy",)},
    {"perms": ("iam:PutUserPolicy",)},
    {"perms": ("iam:PutGroupPolicy",)},
    {"perms": ("iam:PutRolePolicy",)},
    {"perms": ("iam:AddUserToGroup",)},
    {"perms": ("iam:UpdateAssumeRolePolicy",)},
    {
        "perms": ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
        "trusted_principal": "lambda.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping",
        ),
        "trusted_principal": "lambda.amazonaws.com",
    },
    {"perms": ("lambda:AddPermission",)},
    {"perms": ("lambda:UpdateFunctionCode",)},
    {
        "perms": ("iam:PassRole", "glue:CreateDevEndpoint", "glue:GetDevEndpoint"),
        "trusted_principal": "glue.amazonaws.com",
    },
    {
        "perms": ("iam:PassRole", "glue:CreateDevEndpoint", "glue:GetDevEndpoints"),
        "trusted_principal": "glue.amazonaws.com",
    },
    {"perms": ("glue:UpdateDevEndpoint", "glue:GetDevEndpoint")},
    {"perms": ("glue:UpdateDevEndpoint", "glue:GetDevEndpoints")},
    {
        "perms": (
            "iam:PassRole",
            "cloudformation:CreateStack",
            "cloudformation:DescribeStacks",
        ),
        "trusted_principal": "cloudformation.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
            "datapipeline:ActivatePipeline",
        ),
        "trusted_principal": "datapipeline.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "sagemaker:CreateNotebookInstance",
            "sagemaker:StartNotebookInstance",
            "sagemaker:CreatePresignedNotebookInstanceUrl",
        ),
        "trusted_principal": "sagemaker.amazonaws.com",
    },
    {
        "perms": ("iam:PassRole", "glue:CreateJob", "glue:StartJobRun"),
        "trusted_principal": "glue.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "codebuild:CreateProject",
            "codebuild:StartBuild",
        ),
        "trusted_principal": "codebuild.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "codebuild:CreateProject",
            "codebuild:StartBuildBatch",
        ),
        "trusted_principal": "codebuild.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "codebuild:UpdateProject",
            "codebuild:StartBuild",
        ),
        "trusted_principal": "codebuild.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "codebuild:UpdateProject",
            "codebuild:StartBuildBatch",
        ),
        "trusted_principal": "codebuild.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "codepipeline:CreatePipeline",
            "codebuild:CreateProject",
            "codepipeline:StartPipelineExecution",
        ),
        "trusted_principal": "codepipeline.amazonaws.com",
    },
    {
        "perms": (
            "codepipeline:UpdatePipeline",
            "codebuild:UpdateProject",
            "codepipeline:StartPipelineExecution",
        ),
        "trusted_principal": "codepipeline.amazonaws.com",
    },
    {
        "perms": (
            "iam:PassRole",
            "codestar:CreateProject",
        ),
        "trusted_principal": "codestar.amazonaws.com",
    },
]


def main(args: List[str]):
    input_io = Path(args.input).open("rb") if args.input else sys.stdin.buffer
    output_io = Path(args.output).open("w") if args.output else sys.stdout

    data = input_io.read()
    data = json.loads(data)

    statements = extract_trust_policy(data)

    roles = [r["RoleName"] for r in data["RoleDetailList"]]
    privileged_roles = defaultdict(list)
    for role in roles:
        allow_perms, _ = extract_permissions(role, data)
        for privesc_check in privesc_checks:
            privesc_perms = set(privesc_check["perms"])
            privesc_principal = privesc_check.get("trusted_principal")

            if (actions := set(privesc_perms)) == (
                actions & set(allow_perms.keys())
            ) or all(in_glob(set(allow_perms.keys()), p) for p in privesc_perms):
                privileged_roles[role].append(
                    (allow_perms, privesc_perms, privesc_check)
                )

    for privileged_role, checks in privileged_roles.items():
        output_io.write(f"- {privileged_role}\n")

        for allow_perms, actions, privesc_check in checks:
            privesc_perms = privesc_check["perms"]
            privesc_principal = privesc_check.get("trusted_principal")

            output_io.write(
                f"  \_ Privilege Escalation: ({', '.join(privesc_perms)})\n"
            )

            for action in actions:
                output_io.write(f"    \_ Action: {action}\n")

                if p := allow_perms.get(action):
                    rsrcs = p if isinstance(p, list) else [p]
                else:
                    rsrcs = next(
                        r if isinstance(r, list) else [r]
                        for p in privesc_perms
                        for a, r in allow_perms.items()
                        if glob_match(a, p)
                    )

                for r in rsrcs:
                    output_io.write(f"      \_ Resource: {r}\n")
                    if action == "iam:PassRole" and privesc_principal:
                        if (condition_str := " (Condition: ") in r:
                            r, _, cond = r.partition(condition_str)
                            cond = eval(cond[:-1])
                            iamPTS = "iam:PassedToService"
                            svcs = [
                                cond.get("StringEquals", {}).get(iamPTS, []),
                                cond.get("StringLike", {}).get(iamPTS, []),
                                cond.get("StringEqualsIfExists", {}).get(iamPTS, []),
                            ]

                            passed_to_svcs = []
                            for svc in svcs:
                                if isinstance(svc, list):
                                    passed_to_svcs.extend(svc)
                                else:
                                    passed_to_svcs.append(svc)

                            principals = [
                                s
                                for svc in passed_to_svcs
                                for principal_name in statements
                                if glob_match(svc, principal_name)
                                for s in statements[principal_name]["Actions"][
                                    "Allow"
                                ].get("sts:AssumeRole", [])
                            ]
                        else:
                            principals = (
                                statements.get(privesc_principal, {})
                                .get("Actions", {})
                                .get("Allow", {})
                                .get("sts:AssumeRole", [])
                            )

                        for p in principals:
                            p = ":".join(p.split(":")[5:]) if ":" in p else p
                            if glob_match(r, p):
                                if p.strip("role/") in privileged_roles:
                                    output_io.write(f"        \_ {p} (privileged)\n")
                                elif args.verbose:
                                    output_io.write(f"        \_ {p}\n")

                    elif r != "*" and glob_match("iam:*RolePolicy", action):
                        for d in data["RoleDetailList"]:
                            d = ":".join(d["Arn"].split(":")[5:])
                            if glob_match(r, d):
                                output_io.write(f"        \_ {d}\n")
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
