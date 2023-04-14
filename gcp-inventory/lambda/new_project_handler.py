
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer

import json
import os
import time
import datetime
from dateutil import tz

from gcp_lib.project import *
from gcp_lib.common import *

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
            project_id = ddb_record['projectId']['S']
            status = ddb_record['lifecycleState']['S']
            json_record = deseralize(ddb_record)
            if status == "ACTIVE":
                send_message(json_record, os.environ['ACTIVE_TOPIC'])
            else:
                send_message(json_record, os.environ['FOREIGN_TOPIC'])


def send_message(record, topic):
    print(f"Sending Message: {record}")
    sns_client = boto3.client('sns')
    try:
        sns_client.publish(
            TopicArn=topic,
            Subject="New GCP Project",
            Message=json.dumps(record, sort_keys=True, default=str),
        )
    except ClientError as e:
        logger.error(f'Error publishing message: {e}')


def deseralize(ddb_record):
    # This is probablt a semi-dangerous hack.
    # https://github.com/boto/boto3/blob/e353ecc219497438b955781988ce7f5cf7efae25/boto3/dynamodb/types.py#L233
    ds = TypeDeserializer()
    return {k: ds.deserialize(v) for k, v in ddb_record.items()}

