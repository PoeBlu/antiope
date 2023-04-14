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

RESOURCE_PATH = "es/domain"
RESOURCE_TYPE = "AWS::Elasticsearch::Domain"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:

        target_account = AWSAccount(message['account_id'])

        regions = target_account.get_regions()
        if 'region' in message:
            regions = [message['region']]

        # describe ES Domains
        for r in regions:
            es_client = target_account.get_client('es', region=r)

            resource_item = {
                'awsAccountId': target_account.account_id,
                'awsAccountName': target_account.account_name,
                'resourceType': RESOURCE_TYPE,
                'awsRegion': r,
                'source': "Antiope",
            }
            for domain_name in list_domains(es_client, target_account, r):
                response = es_client.describe_elasticsearch_domain(DomainName=domain_name)
                domain = response['DomainStatus']

                resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
                resource_item['configuration']                  = domain
                resource_item['supplementaryConfiguration']     = {}
                resource_item['resourceId']                     = domain['DomainId']
                resource_item['resourceName']                   = domain['DomainName']
                resource_item['ARN']                            = domain['ARN']
                resource_item['errors']                         = {}

                if domain['AccessPolicies']:
                    # The ES Domains' Access policy is returned as a string. Here we parse the json and reapply it to the dict
                    resource_item['supplementaryConfiguration']['AccessPolicies']  = json.loads(domain['AccessPolicies'])

                object_name = f"{domain_name}-{r}-{target_account.account_id}"
                save_resource_to_s3(RESOURCE_PATH, object_name, resource_item)

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


def list_domains(es_client, target_account, region):
    domain_names = []
    response = es_client.list_domain_names()  # This call doesn't support paganiation
    if 'DomainNames' not in response:
        logger.info(
            f"No ElasticSearch domains returned by list_domain_names() for {target_account.account_name}({target_account.account_id}) in {region}"
        )
    else:
        domain_names.extend(d['DomainName'] for d in response['DomainNames'])
    return(domain_names)
