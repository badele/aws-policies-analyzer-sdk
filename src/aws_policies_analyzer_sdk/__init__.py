#!/usr/bin/env python3

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Union

import boto3  # type: ignore

POLICIES_CACHE_FILE = "aws_policies_cache.json"
ROLES_CACHE_FILE = "aws_roles_cache.json"
CROSS_REF_CACHE_FILE = "aws_cross_ref_cache.json"


# Convert python object to json string
def to_json(obj: Any) -> str:
    """
    Converts a Python object to a JSON string with indentation.

    Args:
        obj: The Python object to convert to JSON

    Returns:
        A formatted JSON string representation of the object
    """
    return json.dumps(obj, indent=4, ensure_ascii=False)


def is_policy_managed_by_aws(policy_arn: str) -> bool:
    """
    Checks if an IAM policy is managed by AWS based on its ARN.

    Args:
        policy_arn: The policy ARN to check

    Returns:
        True if the policy is managed by AWS, False otherwise
    """
    return policy_arn.startswith("arn:aws:iam::aws:policy/")


def is_role_managed_by_aws(role_arn: str) -> bool:
    """
    Checks if an IAM role is managed by AWS based on its path.

    Args:
        role_arn: The role path to check

    Returns:
        True if the role is managed by AWS, False otherwise
    """
    return role_arn.startswith(("/aws-service-role/", "/service-role/"))


def extract_service_from_action(action: str) -> str:
    """
    Extracts the AWS service name from an IAM action string.
    Args:
        action: The IAM action string to extract the service name from
    Returns:
        The AWS service name extracted from the action
    """
    service = "all"
    if ":" in action:
        service, _ = action.split(":", 1)

    return service


def slugify(text: str) -> str:
    """
    Converts a string to a slug format by replacing spaces,/,* with dashes.
    Args:
        text: The text to convert to a slug format
    Returns:
        The slugified version of the input text
    """
    return (
        text.lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace(":", "-")
        .replace("*", "all")
    )


def remove_policies_not_managed_by_aws(
    results: List[Optional[Dict[str, Any]]],
) -> List[Optional[Dict[str, Any]]]:
    """
    Filters a list of policy ARNs to include only those managed by AWS.

    Args:
        results: List of policy ARNs to filter

    Returns:
        A list containing only the AWS-managed policy ARNs
    """
    return [
        policy_arn for policy_arn in results if is_policy_managed_by_aws(policy_arn)
    ]


def remove_all_non_managed_by_aws(
    cross_ref: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    # Filter policies to AWS-managed only
    policies_to_keep = {
        policy_arn: data
        for policy_arn, data in cross_ref["policies"].items()
        if is_policy_managed_by_aws(policy_arn)
    }

    # Filter roles to AWS-managed only
    roles_to_keep = {
        role_arn: data
        for role_arn, data in cross_ref["roles"].items()
        if is_role_managed_by_aws(role_arn)
    }

    # Update the cross_ref dictionary with the filtered versions
    cross_ref["policies"] = policies_to_keep
    cross_ref["roles"] = roles_to_keep

    # Update actions to only reference AWS-managed policies and roles
    actions_to_keep = {}
    for action, data in cross_ref["actions"].items():
        filtered_policies = [p for p in data["policies"] if p in policies_to_keep]
        filtered_roles = [r for r in data["roles"] if r in roles_to_keep]

        # Only keep actions that have associated AWS-managed policies or roles
        if filtered_policies or filtered_roles:
            actions_to_keep[action] = {
                "policies": filtered_policies,
                "roles": filtered_roles,
            }

    cross_ref["actions"] = actions_to_keep

    return cross_ref


def find_all_matching_policies(search_string: str, keys: List[str]) -> List[str]:
    """
    Finds all policy keys that contain the given search string.

    Args:
        search_string: The string to search for within policy keys
        keys: List of policy keys to search through

    Returns:
        A list of policy keys that match the search string
    """
    return [key for key in keys if search_string in key]


# Get all policies
def get_all_policies(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves all IAM policies with their details and actions from AWS.
    Uses caching to avoid unnecessary API calls unless forced to refresh.

    Args:
        force_refresh: When True, ignores the cache and fetches fresh data from AWS

    Returns:
        A dictionary of IAM policies with their details, keyed by policy ARN.
        Each policy contains PolicyName, CreateDate, Path, DefaultVersionId, and Actions.
    """
    if not force_refresh and os.path.exists(POLICIES_CACHE_FILE):
        with open(POLICIES_CACHE_FILE, "r") as f:
            return json.loads(f.read())  # type: ignore

    session = boto3.Session()
    iam_client = session.client("iam")

    paginator = iam_client.get_paginator("list_policies")
    policies: Dict[str, Dict[str, Any]] = {}

    # Retrieve all policies
    for page in paginator.paginate(Scope="All"):
        for policy in page["Policies"]:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]

            # Get policy details including statements
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
            )
            document = policy_version["PolicyVersion"]["Document"]
            statements = document.get("Statement", [])

            # Extract actions from policy statements
            actions: List[str] = []
            for statement in statements:
                if "Action" in statement:
                    try:
                        actions.extend(
                            statement["Action"]
                            if isinstance(statement["Action"], list)
                            else [statement["Action"]]
                        )
                    except TypeError:
                        pass

            services = set(extract_service_from_action(action) for action in actions)
            services_list = [service for service in services]

            # Add the policy with its details
            policies[policy_arn] = {
                "PolicyName": policy_name,
                "CreateDate": policy["CreateDate"].strftime("%Y-%m-%d %H:%M:%S"),
                "Path": policy["Path"],
                "DefaultVersionId": policy["DefaultVersionId"],
                "Actions": actions,
                "Service": services_list,
            }

    with open(POLICIES_CACHE_FILE, "w") as f:
        f.write(to_json(policies))

    return policies


def get_all_roles(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves all IAM roles with their attached policies from AWS.
    Uses caching to avoid unnecessary API calls unless forced to refresh.

    Args:
        force_refresh: When True, ignores the cache and fetches fresh data from AWS

    Returns:
        A dictionary of IAM roles with their details, keyed by role ARN.
        Each role contains RoleName, Path, CreateDate, Description, and AttachedPolicies.
    """
    if not force_refresh and os.path.exists(ROLES_CACHE_FILE):
        with open(ROLES_CACHE_FILE, "r") as f:
            return json.loads(f.read())  # type: ignore

    session = boto3.Session()
    iam_client = session.client("iam")

    paginator = iam_client.get_paginator("list_roles")
    roles: Dict[str, Dict[str, Any]] = {}

    # Retrieve all roles
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_arn = role["Arn"]
            role_name = role["RoleName"]

            # Retrieve policies attached to the role
            response = iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get("AttachedPolicies", [])

            policies: List[Dict[str, str]] = []
            for policy in attached_policies:
                policies.append(
                    {
                        "PolicyArn": policy["PolicyArn"],
                        "PolicyName": policy["PolicyName"],
                    }
                )

            # Add the role with its attached policies
            roles[role_arn] = {
                "RoleName": role_name,
                "Path": role["Path"],
                "CreateDate": role["CreateDate"].strftime("%Y-%m-%d %H:%M:%S"),
                "Description": role.get("Description", ""),
                "AttachedPolicies": policies,
            }

    with open(ROLES_CACHE_FILE, "w") as f:
        f.write(to_json(roles))

    return roles


def build_cross_reference_table(
    only_managed_by_aws: bool = False,
    force_refresh: bool = False,
) -> Dict[str, Dict[str, Any]]:
    if not force_refresh and os.path.exists(CROSS_REF_CACHE_FILE):
        with open(CROSS_REF_CACHE_FILE, "r") as f:
            cross_ref = json.loads(f.read())  # type: ignore
            if only_managed_by_aws:
                cross_ref = remove_all_non_managed_by_aws(cross_ref)

            return cross_ref

    all_policies = get_all_policies(force_refresh=force_refresh)
    all_roles = get_all_roles(force_refresh=force_refresh)

    cross_ref = {
        "roles": {},
        "policies": {},
        "actions": {},
        "services": {},
    }

    for policy_arn, policy in all_policies.items():
        policy_name = policy["PolicyName"]
        actions = policy.get("Actions", [])
        services = list(set(extract_service_from_action(action) for action in actions))

        if policy_arn not in cross_ref["policies"]:
            cross_ref["policies"][policy_arn] = {
                "name": policy_name,
                "roles": [],
                "actions": actions,
                "services": services,
            }

        for action in actions:
            service = extract_service_from_action(action)
            if action not in cross_ref["actions"]:
                cross_ref["actions"][action] = {
                    "roles": [],
                    "policies": [],
                    "services": [],
                }

            if policy_arn not in cross_ref["actions"][action]["policies"]:
                cross_ref["actions"][action]["policies"].append(policy_arn)

            if service not in cross_ref["services"]:
                cross_ref["services"][service] = {
                    "roles": [],
                    "policies": [],
                    "actions": [],
                }

            if policy_arn not in cross_ref["services"][service]["policies"]:
                cross_ref["services"][service]["policies"].append(policy_arn)

            if action not in cross_ref["services"][service]["actions"]:
                cross_ref["services"][service]["actions"].append(action)

    for role_arn, role_data in all_roles.items():
        role_name = role_data["RoleName"]
        attached_policies = role_data.get("AttachedPolicies", [])

        if role_arn not in cross_ref["roles"]:
            cross_ref["roles"][role_arn] = {
                "name": role_name,
                "policies": [],
                "actions": [],
                "services": [],
            }

        for policy in attached_policies:
            policy_arn = policy["PolicyArn"]

            if policy_arn not in cross_ref["roles"][role_arn]["policies"]:
                cross_ref["roles"][role_arn]["policies"].append(policy_arn)

            if policy_arn in cross_ref["policies"]:
                if role_arn not in cross_ref["policies"][policy_arn]["roles"]:
                    cross_ref["policies"][policy_arn]["roles"].append(role_arn)

                actions = cross_ref["policies"][policy_arn]["actions"]
                for action in actions:
                    service = extract_service_from_action(action)
                    if action not in cross_ref["roles"][role_arn]["actions"]:
                        cross_ref["roles"][role_arn]["actions"].append(action)

                    if service not in cross_ref["roles"][role_arn]["services"]:
                        cross_ref["roles"][role_arn]["services"].append(service)

                    if action in cross_ref["actions"]:
                        if role_arn not in cross_ref["actions"][action]["roles"]:
                            cross_ref["actions"][action]["roles"].append(role_arn)

                    if service in cross_ref["services"]:
                        if role_arn not in cross_ref["services"][service]["roles"]:
                            cross_ref["services"][service]["roles"].append(role_arn)

    with open(CROSS_REF_CACHE_FILE, "w") as f:
        f.write(to_json(cross_ref))

    if only_managed_by_aws:
        cross_ref = remove_all_non_managed_by_aws(cross_ref)

    return cross_ref


# def build_cross_reference_table(
#     only_managed_by_aws: bool = False,
#     force_refresh: bool = False,
# ) -> Dict[str, Dict[str, Any]]:
#     """
#     Builds a comprehensive cross-reference table between roles, policies, and actions.
#     Creates bidirectional mappings to enable efficient querying in any direction.
#     Uses caching to avoid rebuilding unless forced to refresh.
#
#     Args:
#         force_refresh: When True, forces refresh of policies, roles, and cross-reference cache
#
#     Returns:
#         A dictionary with three main keys ('roles', 'policies', 'actions') containing
#         the relationships between these entities for fast lookup and traversal.
#     """
#
#     # Check if the cache exists and if we're not forcing a refresh
#     if not force_refresh and os.path.exists(CROSS_REF_CACHE_FILE):
#         with open(CROSS_REF_CACHE_FILE, "r") as f:
#             cross_ref = json.loads(f.read())  # type: ignore
#             if only_managed_by_aws:
#                 return remove_all_non_managed_by_aws(cross_ref)
#
#     # If we get here, we need to rebuild the cross-reference table
#     # Retrieve all policies and all roles
#     all_policies = get_all_policies(force_refresh=force_refresh)
#     all_roles = get_all_roles(force_refresh=force_refresh)
#
#     # Initialize the data structure
#     cross_ref: Dict[str, Dict[str, Any]] = {
#         "roles": {},  # role_arn -> {policies: [], actions: []}
#         "policies": {},  # policy_arn -> {roles: [], actions: []}
#         "actions": {},  # action -> {roles: [], policies: []}
#     }
#
#     # Build policy -> actions relationships
#     for policy_arn, policy in all_policies.items():
#         policy_name = policy["PolicyName"]
#         actions = policy.get("Actions", [])
#
#         if policy_arn not in cross_ref["policies"]:
#             cross_ref["policies"][policy_arn] = {
#                 "name": policy_name,
#                 "roles": [],
#                 "actions": actions,
#             }
#
#         # For each action, add this policy
#         for action in actions:
#             if action not in cross_ref["actions"]:
#                 cross_ref["actions"][action] = {"roles": [], "policies": []}
#
#             # Add this policy to the action
#             if policy_arn not in cross_ref["actions"][action]["policies"]:
#                 cross_ref["actions"][action]["policies"].append(policy_arn)
#
#     # Build role -> policies and role -> actions relationships
#     for role_arn, role_data in all_roles.items():
#         role_name = role_data["RoleName"]
#         attached_policies = role_data.get("AttachedPolicies", [])
#
#         # Add the role to the 'roles' section
#         if role_arn not in cross_ref["roles"]:
#             cross_ref["roles"][role_arn] = {
#                 "name": role_name,
#                 "policies": [],
#                 "actions": [],
#             }
#
#         # For each attached policy
#         for policy in attached_policies:
#             policy_arn = policy["PolicyArn"]
#
#             # Add this policy to the role
#             if policy_arn not in cross_ref["roles"][role_arn]["policies"]:
#                 cross_ref["roles"][role_arn]["policies"].append(policy_arn)
#
#             # Add this role to the policy
#             if policy_arn in cross_ref["policies"]:
#                 if role_arn not in cross_ref["policies"][policy_arn]["roles"]:
#                     cross_ref["policies"][policy_arn]["roles"].append(role_arn)
#
#                 # Add the actions of this policy to the role
#                 actions = cross_ref["policies"][policy_arn]["actions"]
#                 for action in actions:
#                     if action not in cross_ref["roles"][role_arn]["actions"]:
#                         cross_ref["roles"][role_arn]["actions"].append(action)
#
#                     # Add this role to the action
#                     if action in cross_ref["actions"]:
#                         if role_arn not in cross_ref["actions"][action]["roles"]:
#                             cross_ref["actions"][action]["roles"].append(role_arn)
#
#     # Save the cross-reference table in the cache
#     with open(CROSS_REF_CACHE_FILE, "w") as f:
#         f.write(to_json(cross_ref))
#
#     if only_managed_by_aws:
#         cross_ref = remove_all_non_managed_by_aws(cross_ref)
#
#     return cross_ref


def query_by_role(
    role_names: Union[str, List[str]],
    only_managed_by_aws: bool = False,
) -> Union[Optional[Dict[str, Any]], List[Optional[Dict[str, Any]]]]:
    """
    Retrieves policies and actions associated with specific IAM roles.

    Args:
        role_names: A single role name or list of role names to query
        only_managed_by_aws: When True, includes only AWS-managed entities in results

    Returns:
        For a single role: A dictionary with the role name, associated policies and actions
        For multiple roles: A list of dictionaries, each containing a role's details
        Returns None for roles that don't exist
    """

    # By default AWS not provide a roles
    if only_managed_by_aws:
        return []

    cross_ref: Dict[str, Dict[str, Any]] = build_cross_reference_table(
        only_managed_by_aws=only_managed_by_aws
    )

    # Convert to list if it's a single string
    single_role = isinstance(role_names, str)
    if single_role:
        role_names = [role_names]  # type: ignore

    results: List[Optional[Dict[str, Any]]] = []
    for role_name in role_names:  # type: ignore
        if role_name not in cross_ref["roles"]:
            continue

        results.append(
            {
                "role": role_name,
                "policies": cross_ref["roles"][role_name]["policies"],
                "actions": cross_ref["roles"][role_name]["actions"],
            }
        )

    return results


def query_by_policy(
    search_policies: Union[str, List[str]],
    only_managed_by_aws: bool = False,
) -> Union[Optional[Dict[str, Any]], List[Optional[Dict[str, Any]]]]:
    """
    Retrieves roles and actions associated with specific IAM policies.
    Supports partial matching of policy ARNs.

    Args:
        search_policies: A single policy ARN/pattern or list of policy ARNs/patterns to search
        only_managed_by_aws: When True, includes only AWS-managed policies in results

    Returns:
        For a single policy search: A dictionary with matched policy ARN, name, associated roles and actions
        For multiple policy searches: A list of dictionaries, each containing a policy's details
        Returns None for policies that don't exist or don't match the search criteria
    """
    cross_ref: Dict[str, Dict[str, Any]] = build_cross_reference_table(
        only_managed_by_aws=only_managed_by_aws
    )

    # Convert to list if it's a single string
    single_policy = isinstance(search_policies, str)
    if single_policy:
        search_policies = [search_policies]  # type: ignore

    results: List[Optional[Dict[str, Any]]] = []
    for search_policy in search_policies:  # type: ignore
        policy_arns = find_all_matching_policies(
            search_policy, cross_ref["policies"].keys()
        )

        for policy_arn in policy_arns:
            if not policy_arn:
                continue

            if only_managed_by_aws and not is_policy_managed_by_aws(policy_arn):
                continue

            results.append(
                {
                    "roles": cross_ref["policies"][policy_arn]["roles"],
                    "policy": policy_arn,
                    "actions": cross_ref["policies"][policy_arn]["actions"],
                    "name": cross_ref["policies"][policy_arn]["name"],
                }
            )

    return results


def query_by_action(
    actions: Union[str, List[str]],
    only_managed_by_aws: bool = False,
) -> Union[Optional[Dict[str, Any]], List[Optional[Dict[str, Any]]]]:
    """
    Retrieves roles and policies associated with specific IAM actions.

    Args:
        actions: A single action name or list of action names to query
        only_managed_by_aws: When True, includes only AWS-managed policies in results

    Returns:
        For a single action: A dictionary with the action name, associated roles and policies
        For multiple actions: A list of dictionaries, each containing an action's details
        Returns None for actions that don't exist
    """
    cross_ref: Dict[str, Dict[str, Any]] = build_cross_reference_table(
        only_managed_by_aws=only_managed_by_aws
    )

    # Convert to list if it's a single string
    single_action = isinstance(actions, str)
    if single_action:
        actions = [actions]  # type: ignore

    results: List[Optional[Dict[str, Any]]] = []
    for action in actions:  # type: ignore
        if action not in cross_ref["actions"]:
            continue

        if only_managed_by_aws:
            cross_ref["actions"][action]["policies"] = (
                remove_policies_not_managed_by_aws(
                    cross_ref["actions"][action]["policies"]
                )
            )

        results.append(
            {
                "roles": cross_ref["actions"][action]["roles"],
                "policies": cross_ref["actions"][action]["policies"],
                "action": action,
            }
        )

    return results


def read_stdin() -> List[str]:
    """
    Reads space-separated data from standard input if available.

    Returns:
        A list of strings read from stdin, or an empty list if stdin is a terminal
    """
    if not sys.stdin.isatty():
        return sys.stdin.read().strip().split()
    return []


def sync_policies() -> Dict[str, int]:
    """
    Forces synchronization of all AWS policies, roles, and cross-reference data.
    Refreshes all caches with the latest data from AWS.

    Returns:
        A dictionary with counts of synchronized entities:
        - policies_count: Number of policies retrieved
        - roles_count: Number of roles retrieved
        - actions_count: Number of unique actions identified
    """

    policies = get_all_policies(force_refresh=True)
    roles = get_all_roles(force_refresh=True)
    cross_ref = build_cross_reference_table(
        only_managed_by_aws=False, force_refresh=True
    )

    return {
        "policies_count": len(policies),
        "roles_count": len(roles),
        "actions_count": len(cross_ref["actions"]),
    }
