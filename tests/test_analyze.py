#!/usr/bin/env python3

import datetime
import json
from unittest.mock import MagicMock, mock_open, patch

import aws_policies_analyzer

POLICY_ARN1 = "arn:aws:iam::aws:policy/TestPolicy1"
POLICY_ARN2 = "arn:aws:iam::aws:policy/TestPolicy2"
POLOCY_NAME1 = "TestPolicy1"
POLICY_NAME2 = "TestPolicy2"
ROLE_ARN1 = "arn:aws:iam::123456789012:role/TestRole1"
ROLE_ARN2 = "arn:aws:iam::123456789012:role/TestRole2"
ROLE_NAME1 = "TestRole1"
ROLE_NAME2 = "TestRole2"


# Tests for to_json function
def test_to_json() -> None:
    test_obj = {"key": "value", "list": [1, 2, 3]}
    result = aws_policies_analyzer.to_json(test_obj)
    assert json.loads(result) == test_obj

    nested_obj = {"nested": {"key": "value"}, "items": [{"id": 1}, {"id": 2}]}
    result = aws_policies_analyzer.to_json(nested_obj)
    assert json.loads(result) == nested_obj


# Tests for get_all_policies function
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open, read_data=json.dumps({"test": "data"}))
def test_get_all_policies_with_cache(
    mock_file: MagicMock, mock_exists: MagicMock
) -> None:
    mock_exists.return_value = True
    result = aws_policies_analyzer.get_all_policies()
    assert result == {"test": "data"}
    mock_file.assert_called_once_with(aws_policies_analyzer.POLICIES_CACHE_FILE, "r")


@patch("boto3.Session")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_get_all_policies_without_cache(
    mock_file: MagicMock, mock_exists: MagicMock, mock_session: MagicMock
) -> None:
    mock_exists.return_value = False

    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client

    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    mock_policy = {
        "Arn": POLICY_ARN1,
        "PolicyName": POLOCY_NAME1,
        "DefaultVersionId": "v1",
        "CreateDate": datetime.datetime(2023, 1, 1, 12, 0, 0),
        "Path": "/",
    }

    mock_paginator.paginate.return_value = [{"Policies": [mock_policy]}]

    mock_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {"Statement": [{"Action": ["s3:GetObject", "s3:PutObject"]}]}
        }
    }

    result = aws_policies_analyzer.get_all_policies()

    assert len(result) == 1
    assert result[mock_policy["Arn"]]["PolicyName"] == mock_policy["PolicyName"]
    assert set(result[mock_policy["Arn"]]["Actions"]) == set(
        ["s3:GetObject", "s3:PutObject"]
    )


# Tests for get_all_roles function
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open, read_data=json.dumps({"test": "data"}))
def test_get_all_roles_with_cache(mock_file: MagicMock, mock_exists: MagicMock) -> None:
    mock_exists.return_value = True
    result = aws_policies_analyzer.get_all_roles()
    assert result == {"test": "data"}
    mock_file.assert_called_once_with(aws_policies_analyzer.ROLES_CACHE_FILE, "r")


@patch("boto3.Session")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_get_all_roles_without_cache(
    mock_file: MagicMock, mock_exists: MagicMock, mock_session: MagicMock
) -> None:
    mock_exists.return_value = False

    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client

    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    mock_role = {
        "RoleName": "TestRole",
        "RoleId": "AROAXXXXXXXXXXXXXXXXX",
        "Arn": "arn:aws:iam::123456789012:role/TestRole",
        "Path": "/",
        "CreateDate": datetime.datetime(2023, 1, 1, 12, 0, 0),
        "Description": "Test role",
    }

    mock_paginator.paginate.return_value = [{"Roles": [mock_role]}]

    mock_client.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyArn": POLICY_ARN1,
                "PolicyName": POLOCY_NAME1,
            }
        ]
    }

    result = aws_policies_analyzer.get_all_roles()

    assert len(result) == 1
    assert result[mock_role["Arn"]]["RoleName"] == mock_role["RoleName"]
    assert result[mock_role["Arn"]]["CreateDate"] == "2023-01-01 12:00:00"
    assert len(result[mock_role["Arn"]]["AttachedPolicies"]) == 1


##############################################################################
# test_build_cross_reference_table_with_valid_cache
##############################################################################

# Load mock data from file
with open("tests/datas/mock_cross_ref.json", "r") as f:
    mock_data = json.load(f)


# Tests for build_cross_reference_table function
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open, read_data=json.dumps(mock_data))
def test_build_cross_reference_table_with_valid_cache(
    mock_file: MagicMock, mock_exists: MagicMock
) -> None:
    mock_exists.return_value = True

    result = aws_policies_analyzer.build_cross_reference_table()

    assert result == mock_data
    assert "roles" in result
    assert "policies" in result
    assert "actions" in result
    assert "services" in result
    assert result["policies"][POLICY_ARN1]["name"] == POLOCY_NAME1
    assert result["actions"]["ec2:*"]["policies"] == [
        POLICY_ARN1,
        POLICY_ARN2,
    ]
    assert result["services"]["ec2"]["actions"] == ["ec2:*"]


@patch("aws_policies_analyzer.get_all_policies")
@patch("aws_policies_analyzer.get_all_roles")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_build_cross_reference_table_from_scratch(
    mock_file: MagicMock,
    mock_exists: MagicMock,
    mock_get_all_roles: MagicMock,
    mock_get_all_policies: MagicMock,
) -> None:
    mock_exists.return_value = False

    mock_get_all_policies.return_value = {
        POLICY_ARN1: {
            "PolicyName": POLOCY_NAME1,
            "Actions": ["s3:GetObject", "s3:PutObject"],
            "CreateDate": "2023-01-01 12:00:00",
            "Path": "/",
            "DefaultVersionId": "v1",
            "Service": ["s3"],
        }
    }

    mock_get_all_roles.return_value = {
        ROLE_ARN1: {
            "RoleName": ROLE_NAME1,
            "Path": "/",
            "CreateDate": "2023-01-01 12:00:00",
            "Description": "Test role",
            "AttachedPolicies": [
                {
                    "PolicyArn": POLICY_ARN1,
                    "PolicyName": POLOCY_NAME1,
                }
            ],
        }
    }

    result = aws_policies_analyzer.build_cross_reference_table()

    assert "roles" in result
    assert "policies" in result
    assert "actions" in result
    assert "arn:aws:iam::123456789012:role/TestRole1" in result["roles"]
    assert "s3:GetObject" in result["actions"]


# Tests for query functions
@patch("aws_policies_analyzer.build_cross_reference_table")
def test_query_by_role(mock_build_cross_ref: MagicMock) -> None:
    mock_build_cross_ref.return_value = {
        "roles": {
            ROLE_ARN1: {
                "name": ROLE_NAME1,
                "policies": [POLICY_ARN1],
                "actions": ["s3:GetObject", "s3:PutObject"],
                "services": ["s3"],
            }
        }
    }

    # Test with single role
    result = aws_policies_analyzer.query_by_role(ROLE_ARN1)
    assert result is not None
    assert result[0]["role"] == ROLE_ARN1
    assert POLICY_ARN1 in result[0]["policies"]
    assert "s3:GetObject" in result[0]["actions"]

    # Test with list of roles
    results = aws_policies_analyzer.query_by_role([ROLE_ARN1])
    assert len(results) == 1
    assert results[0] is not None
    assert results[0]["role"] == ROLE_ARN1

    # Test with non-existent role
    result_none = aws_policies_analyzer.query_by_role(
        "arn:aws:iam::123456789012:role/NonExistentRole"
    )
    assert len(result_none) == 0

    # Test with list containing non-existent role
    results_mixed = aws_policies_analyzer.query_by_role(
        [
            ROLE_ARN1,
            "arn:aws:iam::123456789012:role/NonExistentRole",
        ]
    )

    assert len(results_mixed) == 1
    assert results_mixed[0]["role"] == ROLE_ARN1
    assert POLICY_ARN1 in results_mixed[0]["policies"]
    assert "s3:GetObject" in results_mixed[0]["actions"]


@patch("aws_policies_analyzer.build_cross_reference_table")
def test_query_by_policy(mock_build_cross_ref: MagicMock) -> None:
    policy_arn = POLICY_ARN1
    mock_build_cross_ref.return_value = {
        "policies": {
            policy_arn: {
                "name": POLOCY_NAME1,
                "roles": [
                    ROLE_ARN1,
                    ROLE_ARN2,
                ],
                "actions": ["s3:GetObject", "s3:PutObject"],
                "services": ["s3"],
            }
        }
    }

    # Test with single policy
    result = aws_policies_analyzer.query_by_policy(policy_arn)
    assert result is not None
    assert result[0]["policy"] == policy_arn
    assert ROLE_ARN1 in result[0]["roles"]
    assert "s3:GetObject" in result[0]["actions"]

    # Test with list of policies
    results = aws_policies_analyzer.query_by_policy([policy_arn])
    assert len(results) == 1
    assert results[0] is not None
    assert results[0]["policy"] == policy_arn

    # Test with non-existent policy
    result_none = aws_policies_analyzer.query_by_policy(
        "arn:aws:iam::aws:policy/NonExistentPolicy"
    )
    assert len(result_none) == 0

    # Test with list containing non-existent policy
    results_mixed = aws_policies_analyzer.query_by_policy(
        [policy_arn, "arn:aws:iam::aws:policy/NonExistentPolicy"]
    )
    assert len(results_mixed) == 1
    assert results_mixed[0] is not None
    assert results_mixed[0]["policy"] == policy_arn


@patch("aws_policies_analyzer.build_cross_reference_table")
def test_query_by_action(mock_build_cross_ref: MagicMock) -> None:
    action = "s3:GetObject"
    mock_build_cross_ref.return_value = {
        "actions": {
            action: {
                "roles": [
                    ROLE_ARN1,
                    ROLE_ARN2,
                ],
                "policies": [POLICY_ARN1],
            }
        }
    }

    # Test with single action
    result = aws_policies_analyzer.query_by_action(action)
    assert result is not None
    assert result[0]["action"] == action
    assert ROLE_ARN1 in result[0]["roles"]
    assert POLICY_ARN1 in result[0]["policies"]

    # Test with list of actions
    results = aws_policies_analyzer.query_by_action([action])
    assert len(results) == 1
    assert results[0] is not None
    assert results[0]["action"] == action

    # Test with non-existent action
    result_none = aws_policies_analyzer.query_by_action("NonExistentAction")
    assert len(result_none) == 0

    # Test with list containing non-existent action
    results_mixed = aws_policies_analyzer.query_by_action([action, "NonExistentAction"])
    assert len(results_mixed) == 1
    assert results_mixed[0] is not None
    assert results_mixed[0]["action"] == action


# Test for read_stdin
@patch("sys.stdin")
def test_read_stdin(mock_stdin: MagicMock) -> None:
    mock_stdin.isatty.return_value = False
    mock_stdin.read.return_value = "line1 line2 line3"

    result = aws_policies_analyzer.read_stdin()
    assert result == ["line1", "line2", "line3"]

    mock_stdin.isatty.return_value = True
    result = aws_policies_analyzer.read_stdin()
    assert result == []


# Test for main function
@patch("aws_policies_analyzer.cli.query_by_role")
@patch("aws_policies_analyzer.cli.to_json")
@patch("builtins.print")
@patch(
    "sys.argv",
    ["aws_policies_analyzer", "--by-role", ROLE_NAME1],
)
def test_main(
    mock_print: MagicMock, mock_to_json: MagicMock, mock_query_by_role: MagicMock
) -> None:
    mock_query_by_role.return_value = {"test": "data"}
    mock_to_json.return_value = '{"test": "data"}'

    from aws_policies_analyzer.cli import main

    main()

    mock_query_by_role.assert_called_once_with([ROLE_NAME1], False)
    mock_to_json.assert_called_once_with({"test": "data"})
    mock_print.assert_called_once_with('{"test": "data"}')
