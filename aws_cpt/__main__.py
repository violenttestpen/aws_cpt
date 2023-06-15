#!/usr/bin/env python3

import argparse
from typing import List

from aws_cpt.modules import (
    gather_assume_role,
    gather_permissions_for_role,
    gather_privesc,
    gather_resource_exposure,
    gather_who_has,
)


def main():
    parser = argparse.ArgumentParser()

    cmd_parsers = parser.add_subparsers(dest="cmd", required=True)

    parsers = {}
    for cmd in ("assume_role", "permission", "privesc", "resource_exposure", "who_has"):
        subparser = cmd_parsers.add_parser(cmd)
        subparser.add_argument(
            "--input",
            "-i",
            help="The filepath to the output of `iam get-account-authorization-details`",
        )
        subparser.add_argument(
            "--output",
            "-o",
            help="The filepath to save the results",
        )
        subparser.add_argument(
            "--verbose",
            "-v",
            default=False,
            action="store_true",
            help="Verbose mode",
        )
        parsers[cmd] = subparser

    parsers["permission"].add_argument(
        "--reverse",
        "-r",
        default=False,
        action="store_true",
        help="Show actions grouped by resources instead",
    )
    parsers["permission"].add_argument("role", help="Roles that are in scope")

    parsers["resource_exposure"].add_argument(
        "--reverse",
        "-r",
        default=False,
        action="store_true",
        help="Show actions grouped by resources instead",
    )

    parsers["who_has"].add_argument(
        "permission", nargs="+", help="Filter using specified permission(s)"
    )

    args = parser.parse_args()

    if args.cmd == "assume_role":
        gather_assume_role.main(args)
    elif args.cmd == "permission":
        gather_permissions_for_role.main(args)
    elif args.cmd == "privesc":
        gather_privesc.main(args)
    elif args.cmd == "resource_exposure":
        gather_resource_exposure.main(args)
    elif args.cmd == "who_has":
        gather_who_has.main(args)


if __name__ == "__main__":
    main()
