#!/usr/bin/env python3
"""
AWS IAM Policies CLI Tool.

Command-line interface for analyzing AWS IAM policies, roles, and their relationships.
Provides functionality to query by role, policy, or action, as well as synchronize
AWS policies data locally.
"""

import argparse


from aws_policies_analyzer import (
    query_by_action,
    query_by_policy,
    query_by_role,
    sync_policies,
    to_json,
)


def main() -> None:
    """
    Parse command-line arguments and execute the appropriate AWS policy analysis operation.

    The CLI supports the following main commands:
    - Query by role name
    - Query by policy ARN
    - Query by action
    - Synchronize all AWS policies and roles data

    Returns:
        None: Results are printed to stdout in JSON format
    """
    parser = argparse.ArgumentParser(description="AWS IAM Policies CLI Tool")

    # Main commands
    main_group = parser.add_mutually_exclusive_group(required=True)
    main_group.add_argument(
        "--by-role",
        type=str,
        nargs="+",
        help="Search by role (can take multiple values)",
    )
    main_group.add_argument(
        "--by-policy",
        type=str,
        nargs="+",
        help="Search by policy(ARN) (can take multiple values)",
    )
    main_group.add_argument(
        "--by-action",
        type=str,
        nargs="+",
        help="Search by action (can take multiple values)",
    )
    main_group.add_argument(
        "--sync-policies",
        action="store_true",
        help="Force synchronization of all AWS policies, roles, and cross-reference data",
    )

    # Options
    parser.add_argument(
        "--only-managed-by-aws",
        action="store_true",
        help="Only include roles and policies managed by AWS",
    )

    args = parser.parse_args()

    # Command processing
    if args.by_role:
        print(to_json(query_by_role(args.by_role, args.only_managed_by_aws)))
    elif args.by_policy:
        print(to_json(query_by_policy(args.by_policy, args.only_managed_by_aws)))
    elif args.by_action:
        print(to_json(query_by_action(args.by_action, args.only_managed_by_aws)))
    elif args.sync_policies:
        result = sync_policies()
        print(to_json(result))
    else:
        print("Error: Command not recognized")


if __name__ == "__main__":
    main()
