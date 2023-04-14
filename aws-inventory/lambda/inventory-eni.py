
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

RESOURCE_PATH = "ec2/eni"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:
        target_account = AWSAccount(message['account_id'])
        for r in target_account.get_regions():
            discover_enis(target_account, r)

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


def discover_enis(account, region):
    '''
        Queries AWS to gather up the public IP addresses and stores them in DynamoDB
        Will Return an array of objects put in the table

    '''
    s3client = boto3.client('s3')

    resource_item = {
        'awsAccountId': account.account_id,
        'awsAccountName': account.account_name,
        'resourceType': "AWS::EC2::NetworkInterface",
        'source': "Antiope",
        'awsRegion': region,
    }
    interfaces = []

    # Not all Public IPs are attached to instances. So we use ec2 describe_network_interfaces()
    # All results are saved to S3. Public IPs and metadata go to DDB (based on the the presense of PublicIp in the Association)
    ec2_client = account.get_client('ec2', region=region)
    response = ec2_client.describe_network_interfaces()
    while 'NextToken' in response:  # Gotta Catch 'em all!
        interfaces += response['NetworkInterfaces']
        response = ec2_client.describe_network_interfaces(NextToken=response['NextToken'])
    interfaces += response['NetworkInterfaces']

    for eni in interfaces:

        resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
        resource_item['configuration']                  = eni
        resource_item['tags']                           = eni['TagSet']
        resource_item['supplementaryConfiguration']     = {}
        resource_item['resourceId']                     = eni['NetworkInterfaceId']
        resource_item['resourceName']                   = eni['NetworkInterfaceId']
        resource_item['errors']                         = {}
        save_resource_to_s3(RESOURCE_PATH, resource_item['resourceId'], resource_item)

        # Now build up the Public IP Objects
        if 'Association' in eni and 'PublicIp' in eni['Association']:
            try:
                object_key = f"PublicIPs/{eni['Association']['PublicIp']}.json"
                s3client.put_object(
                    Body=json.dumps(eni, sort_keys=True, default=str, indent=2),
                    Bucket=os.environ['INVENTORY_BUCKET'],
                    ContentType='application/json',
                    Key=object_key,
                )
            except ClientError as e:
                logger.error(f"Unable to save object {object_key}: {e}")


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")
