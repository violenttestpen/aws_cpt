#!/usr/bin/env python3

import argparse
from typing import List

from aws_cpt.modules import (
    gather_assume_role,
    gather_permissions_for_role,
    gather_privesc,
)


def main():
    parser = argparse.ArgumentParser()

    cmd_parsers = parser.add_subparsers(dest="cmd", required=True)

    assume_role_parser = cmd_parsers.add_parser("assume_role")
    assume_role_parser.add_argument(
        "--input",
        "-i",
        help="The filepath to the output of `iam get-account-authorization-details`",
    )
    assume_role_parser.add_argument(
        "--output",
        "-o",
        help="The filepath to save the results",
    )
    assume_role_parser.add_argument(
        "--verbose",
        "-v",
        default=False,
        action="store_true",
        help="Verbose mode",
    )

    permission_parser = cmd_parsers.add_parser("permission")
    permission_parser.add_argument(
        "--input",
        "-i",
        help="The filepath to the output of `iam get-account-authorization-details`",
    )
    permission_parser.add_argument(
        "--output",
        "-o",
        help="The filepath to save the results",
    )
    permission_parser.add_argument(
        "--verbose",
        "-v",
        default=False,
        action="store_true",
        help="Verbose mode",
    )
    permission_parser.add_argument(
        "--reverse",
        "-r",
        default=False,
        action="store_true",
        help="Show actions grouped by resources instead",
    )
    permission_parser.add_argument("role", help="Roles that are in scope")

    privesc_parser = cmd_parsers.add_parser("privesc")
    privesc_parser.add_argument(
        "--input",
        "-i",
        help="The filepath to the output of `iam get-account-authorization-details`",
    )
    privesc_parser.add_argument(
        "--output",
        "-o",
        help="The filepath to save the results",
    )
    privesc_parser.add_argument(
        "--verbose",
        "-v",
        default=False,
        action="store_true",
        help="Verbose mode",
    )

    args = parser.parse_args()

    if args.cmd == "assume_role":
        gather_assume_role.main(args)
    elif args.cmd == "permission":
        gather_permissions_for_role.main(args)
    elif args.cmd == "privesc":
        gather_privesc.main(args)


if __name__ == "__main__":
    main()
