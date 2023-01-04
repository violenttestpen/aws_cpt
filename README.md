# AWS Cloud Pentest Utility

Helper scripts for a quicker Cloud PT on AWS environments

## Commands

All commands require the output of the `aws iam get-account-authorization-details` JSON document to be supplied as `INPUT`.

### assume_role

Displays all IAM roles that IAM principals that are able to perform `sts:AssumeRole` on.

```
usage: awscpt assume_role [-h] [--input INPUT] [--output OUTPUT] [--verbose]

options:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        The filepath to the output of `iam get-account-authorization-details`
  --output OUTPUT, -o OUTPUT
                        The filepath to save the results
  --verbose, -v         Verbose mode
```

### permission

Expands and displays all permissions of a selected role based on its inline policies, attached managed policies, etc.

```
usage: awscpt permission [-h] [--input INPUT] [--output OUTPUT] [--verbose] [--reverse] role

positional arguments:
  role                  Roles that are in scope

options:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        The filepath to the output of `iam get-account-authorization-details`
  --output OUTPUT, -o OUTPUT
                        The filepath to save the results
  --verbose, -v         Verbose mode
  --reverse, -r         Show actions grouped by resources instead
```

### privesc

Displays known privilege escalation patterns on IAM roles. If the target resource has a wildcard, it attempts to match existing roles with the target role and displays it if the role is privileged (default) or otherwise (verbose mode).

```
usage: awscpt privesc [-h] [--input INPUT] [--output OUTPUT] [--verbose]

options:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        The filepath to the output of `iam get-account-authorization-details`
  --output OUTPUT, -o OUTPUT
                        The filepath to save the results
  --verbose, -v         Verbose mode
```

# Installation

## Method 1 - Using [pipx](https://pypa.github.io/pipx/) (Recommended)

```
pipx install git+https://github.com/violenttestpen/aws_cpt.git
```

# Method 2 - Using pip

```
pip install --user git+https://github.com/violenttestpen/aws_cpt.git
```
