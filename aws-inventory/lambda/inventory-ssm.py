import boto3
from botocore.exceptions import ClientError

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

INSTANCE_RESOURCE_PATH = "ssm/managedinstance"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:
        target_account = AWSAccount(message['account_id'])

        regions = target_account.get_regions()
        if 'region' in message:
            regions = [message['region']]

        # describe ec2 instances
        for r in regions:
            client = target_account.get_client('ssm', region=r)
            process_instances(target_account, client, r)

    except AntiopeAssumeRoleError as e:
        logger.error(
            f"Unable to assume role into account {target_account.account_name}({target_account.account_id})"
        )
        return()
    except ClientError as e:
        logger.critical(
            f"AWS Error getting info for {target_account.account_name}: {e}"
        )
        raise
    except Exception as e:
        logger.critical(f"{e}\nMessage: {message}\nContext: {vars(context)}")
        raise


def process_instances(target_account, client, region):

    instances = get_all_instances(client)
    logger.info(
        f"Found {len(instances)} managed instances for {target_account.account_id} in {region}"
    )

    # dump info about instances to S3 as json
    for instance in instances:
        resource_item = {
            'awsAccountId': target_account.account_id,
            'awsAccountName': target_account.account_name,
            'resourceType': "AWS::SSM::ManagedInstanceInventory",
            'source': "Antiope",
            'configurationItemCaptureTime': str(datetime.datetime.now()),
        }
        resource_item['awsRegion']                      = region
        resource_item['configuration']                  = instance
        resource_item['supplementaryConfiguration']     = {}
        resource_item['resourceId']                     = instance['InstanceId']
        resource_item['errors']                         = {}
        save_resource_to_s3(INSTANCE_RESOURCE_PATH, resource_item['resourceId'], resource_item)


def get_all_instances(client):
    output = []
    response = client.describe_instance_information()
    while 'NextToken' in response:
        output += response['InstanceInformationList']
        response = client.describe_instance_information(NextToken=response['NextToken'])
    output += response['InstanceInformationList']
    return(output)
