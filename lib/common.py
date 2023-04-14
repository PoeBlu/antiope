import json
import os
import time
import datetime
from dateutil import tz
import logging

import boto3
from botocore.exceptions import ClientError

from lib.account import *
from lib.foreign_account import *


def parse_tags(tagset):
    """Convert the tagset as returned by AWS into a normal dict of {"tagkey": "tagvalue"}"""
    return {tag['Key']: tag['Value'] for tag in tagset}


def save_resource_to_s3(prefix, resource_id, resource):
    """Saves the resource to S3 in prefix with the object name of resource_id.json"""
    s3client = boto3.client('s3')
    try:
        object_key = f"Resources/{prefix}/{resource_id}.json"
        s3client.put_object(
            Body=json.dumps(resource, sort_keys=True, default=str, indent=2),
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='application/json',
            Key=object_key,
        )
    except ClientError as e:
        logger.error(f"Unable to save object {object_key}: {e}")


def get_active_accounts(table_name=None):
    """Returns an array of all active AWS accounts as AWSAccount objects"""
    account_ids = get_account_ids(status="ACTIVE", table_name=table_name)
    return [AWSAccount(a) for a in account_ids]


def get_foreign_accounts():
    """Returns an array of all active AWS accounts as AWSAccount objects"""
    foreign_account_ids = get_account_ids(status="FOREIGN")
    trusted_account_ids = get_account_ids(status="TRUSTED")
    output = [ForeignAWSAccount(a) for a in trusted_account_ids]
    output.extend(ForeignAWSAccount(a) for a in foreign_account_ids)
    return(output)


def get_account_ids(status=None, table_name=None):
    """return an array of account_ids from the Accounts table. Optionally, filter by status"""
    dynamodb = boto3.resource('dynamodb')
    if table_name:
        account_table = dynamodb.Table(table_name)
    else:
        account_table = dynamodb.Table(os.environ['ACCOUNT_TABLE'])

    account_list = []
    response = account_table.scan(
        AttributesToGet=['account_id', 'account_status']
    )
    while 'LastEvaluatedKey' in response:
        # Means that dynamoDB didn't return the full set, so ask for more.
        account_list = account_list + response['Items']
        response = account_table.scan(
            AttributesToGet=['account_id', 'account_status'],
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
    account_list = account_list + response['Items']
    return [
        a['account_id']
        for a in account_list
        if status is None or a['account_status'] == status
    ]


def set_debug(event, logger):
    """Given the event, and using the environment, decide if the logger default should be overridden."""
    if 'debug' in event and event['debug']:
        logger.setLevel(logging.DEBUG)

    if 'DEBUG' in os.environ and os.environ['DEBUG'] == "True":
        logger.setLevel(logging.DEBUG)
    return(logger)
