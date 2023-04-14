
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer

import json
import os
import time
import datetime
from dateutil import tz

from lib.account import *
from lib.common import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")

    for record in event['Records']:
        if record['eventSource'] != "aws:dynamodb":
            next
        if record['eventName'] == "INSERT":
            ddb_record = record['dynamodb']['NewImage']
            logger.debug(ddb_record)
            account_id = ddb_record['account_id']['S']
            account_type = ddb_record['account_status']['S']
            json_record = deseralize(ddb_record)
            if account_type == "ACTIVE":
                send_message(json_record, os.environ['ACTIVE_TOPIC'])
            elif account_type == "FOREIGN":
                send_message(json_record, os.environ['FOREIGN_TOPIC'])


def send_message(record, topic):
    print(f"Sending Message: {record}")
    sns_client = boto3.client('sns')
    try:
        sns_client.publish(
            TopicArn=topic,
            Subject="NewAccount",
            Message=json.dumps(record, sort_keys=True, default=str),
        )
    except ClientError as e:
        logger.error(f'Error publishing message: {e}')


def deseralize(ddb_record):
    # This is probablt a semi-dangerous hack.
    # https://github.com/boto/boto3/blob/e353ecc219497438b955781988ce7f5cf7efae25/boto3/dynamodb/types.py#L233
    ds = TypeDeserializer()
    return {k: ds.deserialize(v) for k, v in ddb_record.items()}
