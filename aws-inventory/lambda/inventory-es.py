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
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Received message: " + json.dumps(message, sort_keys=True))

    try:

        target_account = AWSAccount(message['account_id'])

        regions = target_account.get_regions()
        if 'region' in message:
            regions = [message['region']]

        # describe ES Domains
        for r in regions:
            es_client = target_account.get_client('es', region=r)

            resource_item = {}
            resource_item['awsAccountId']                   = target_account.account_id
            resource_item['awsAccountName']                 = target_account.account_name
            resource_item['resourceType']                   = RESOURCE_TYPE
            resource_item['awsRegion']                      = r
            resource_item['source']                         = "Antiope"

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

                object_name = "{}-{}-{}".format(domain_name, r, target_account.account_id)
                save_resource_to_s3(RESOURCE_PATH, object_name, resource_item)

    except AntiopeAssumeRoleError as e:
        logger.error("Unable to assume role into account {}({})".format(target_account.account_name, target_account.account_id))
        return()
    except ClientError as e:
        logger.critical("AWS Error getting info for {}: {}".format(target_account.account_name, e))
        raise
    except Exception as e:
        logger.critical("{}\nMessage: {}\nContext: {}".format(e, message, vars(context)))
        raise


def list_domains(es_client, target_account, region):
    domain_names = []
    response = es_client.list_domain_names()  # This call doesn't support paganiation
    if 'DomainNames' not in response:
        logger.info("No ElasticSearch domains returned by list_domain_names() for {}({}) in {}".format(
            target_account.account_name,
            target_account.account_id,
            region
        ))
    else:
        for d in response['DomainNames']:
            domain_names.append(d['DomainName'])
    return(domain_names)
