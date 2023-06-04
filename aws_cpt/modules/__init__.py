#!/usr/bin/env python3

import argparse


def create_new_argparser() -> argparse.ArgumentParser:
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
    return parser
