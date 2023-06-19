#!/usr/bin/env python3

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List

DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"


def glob_match(pattern: str, data: str) -> bool:
    pattern, data = pattern.lower(), data.lower()

    if "*" not in pattern:
        return pattern == data

    index = 0
    while "*" in pattern:
        pattern_part, _, pattern = pattern.partition("*")
        if (index := data.find(pattern_part, index)) == -1:
            return False
        index += len(pattern_part)

    return (pattern in data) or (data in pattern)


def in_glob(patterns: Iterable[str], data: str) -> bool:
    return any(glob_match(p, data) for p in patterns)


def in_glob2(pattern: str, datas: Iterable[str]) -> bool:
    return any(glob_match(pattern, d) for d in datas)


def _parse_datetime_string(date: str) -> datetime:
    return date
    # try:
    #     return datetime.fromisoformat(date)
    # except ValueError:
    #     return datetime.fromisoformat(date.replace("Z", "+00:00"))


@dataclass
class Principal:
    Type: str
    Name: str


@dataclass
class PolicyStatement:
    Effect: str
    Condition: object = None
    Principal: List[Principal] = None
    Action: List[str] = field(default_factory=list)
    NotAction: List[str] = field(default_factory=list)
    Resource: List[str] = field(default_factory=list)
    NotResource: List[str] = field(default_factory=list)
    Sid: str = None

    def __post_init__(self):
        if isinstance(self.Action, str):
            self.Action = [self.Action]
        if isinstance(self.Resource, str):
            self.Resource = [self.Resource]
        if isinstance(self.NotResource, str):
            self.NotResource = [self.NotResource]
        if self.Principal:
            principals = []
            for type, name in self.Principal.items():
                if isinstance(name, list):
                    principals.extend(Principal(type, n) for n in name)
                else:
                    principals.append(Principal(type, name))
            self.Principal = principals


@dataclass
class PolicyDocument:
    Statement: List[PolicyStatement]
    Version: str = None
    Id: str = None

    def __post_init__(self):
        if not isinstance(self.Statement, list):
            self.Statement = [self.Statement]
        self.Statement = [PolicyStatement(**s) for s in self.Statement]


@dataclass
class RolePolicy:
    PolicyName: str
    PolicyDocument: PolicyDocument

    def __post_init__(self):
        self.PolicyDocument = PolicyDocument(**self.PolicyDocument)


@dataclass
class Role:
    Path: str
    RoleName: str
    RoleId: str
    Arn: str
    CreateDate: datetime
    AssumeRolePolicyDocument: PolicyDocument
    InstanceProfileList: list
    RolePolicyList: List[RolePolicy]
    AttachedManagedPolicies: Dict[str, str]
    Tags: list
    RoleLastUsed: object
    PermissionsBoundary: list = field(default_factory=list)

    def __post_init__(self):
        self.CreateDate = _parse_datetime_string(self.CreateDate)
        self.AssumeRolePolicyDocument = PolicyDocument(**self.AssumeRolePolicyDocument)
        self.RolePolicyList = [RolePolicy(**rp) for rp in self.RolePolicyList]


@dataclass
class PolicyVersionDocument:
    Document: PolicyDocument
    VersionId: str
    IsDefaultVersion: bool
    CreateDate: datetime

    def __post_init__(self):
        self.CreateDate = _parse_datetime_string(self.CreateDate)
        self.Document = PolicyDocument(**self.Document)


@dataclass
class Policy:
    PolicyName: str
    PolicyId: str
    Arn: str
    Path: str
    DefaultVersionId: str
    AttachmentCount: int
    PermissionsBoundaryUsageCount: int
    IsAttachable: bool
    CreateDate: datetime
    UpdateDate: datetime
    PolicyVersionList: List[PolicyVersionDocument]

    def __post_init__(self):
        self.CreateDate = _parse_datetime_string(self.CreateDate)
        self.UpdateDate = _parse_datetime_string(self.UpdateDate)
        self.PolicyVersionList = [
            PolicyVersionDocument(**p) for p in self.PolicyVersionList
        ]


@dataclass
class User:
    Path: str
    UserName: str
    UserId: str
    Arn: str
    CreateDate: datetime
    AttachedManagedPolicies: Dict[str, str]
    UserPolicyList: list = field(default_factory=list)
    GroupList: list = field(default_factory=list)
    PermissionsBoundary: list = field(default_factory=list)
    Tags: list = field(default_factory=list)

    def __post_init__(self):
        self.CreateDate = _parse_datetime_string(self.CreateDate)


@dataclass
class Group:
    Path: str
    GroupName: str
    GroupId: str
    Arn: str
    CreateDate: datetime
    GroupPolicyList: list
    AttachedManagedPolicies: Dict[str, str]

    def __post_init__(self):
        self.CreateDate = _parse_datetime_string(self.CreateDate)


@dataclass
class IAMDocument:
    UserDetailList: List[User]
    GroupDetailList: List[Group]
    RoleDetailList: List[Role]
    Policies: List[Policy]

    def __post_init__(self):
        self.UserDetailList = [User(**d) for d in self.UserDetailList]
        self.GroupDetailList = [Group(**d) for d in self.GroupDetailList]
        self.RoleDetailList = [Role(**d) for d in self.RoleDetailList]
        self.Policies = [Policy(**d) for d in self.Policies]
