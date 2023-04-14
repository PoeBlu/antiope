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

RESOURCE_PATH = "cloudfront/distribution"
RESOURCE_TYPE = "AWS::CloudFront::Distribution"


def lambda_handler(event, context):
    set_debug(event, logger)
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:

        target_account = AWSAccount(message['account_id'])

        # Cloudfront is a global service
        cf_client = target_account.get_client('cloudfront')

        resource_item = {
            'awsAccountId': target_account.account_id,
            'awsAccountName': target_account.account_name,
            'resourceType': RESOURCE_TYPE,
            'source': "Antiope",
        }
        for distribution in list_distributions(cf_client, target_account):

            resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
            resource_item['configuration']                  = distribution
            resource_item['supplementaryConfiguration']     = {}
            resource_item['resourceId']                     = distribution['Id']
            resource_item['resourceName']                   = distribution['DomainName']
            resource_item['ARN']                            = distribution['ARN']
            resource_item['errors']                         = {}

            save_resource_to_s3(RESOURCE_PATH, distribution['Id'], resource_item)

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


def list_distributions(cf_client, target_account):
    distributions = []
    response = cf_client.list_distributions()
    while 'NextMarker' in response['DistributionList']:
        distributions.extend(iter(response['DistributionList']['Items']))
        response = cf_client.list_distributions(Marker=response['NextMarker'])
    if 'Items' not in response['DistributionList']:
        return(distributions)
    distributions.extend(iter(response['DistributionList']['Items']))
    return(distributions)
