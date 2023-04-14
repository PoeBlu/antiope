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

INSTANCE_RESOURCE_PATH = "ec2/instance"
SG_RESOURCE_PATH = "ec2/securitygroup"


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
            ec2_client = target_account.get_client('ec2', region=r)
            process_instances(target_account, ec2_client, r)

            # describe ec2 security groups
            process_securitygroups(target_account, ec2_client, r)

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


def process_instances(target_account, ec2_client, region):

    instance_profiles = get_instance_profiles(ec2_client)
    instance_reservations = get_all_instances(ec2_client)
    logger.info(
        f"Found {len(instance_reservations)} instance reservations for {target_account.account_id} in {region}"
    )

    # dump info about instances to S3 as json
    for reservation in instance_reservations:
        for instance in reservation['Instances']:

            resource_item = {
                'awsAccountId': target_account.account_id,
                'awsAccountName': target_account.account_name,
                'resourceType': "AWS::EC2::Instance",
                'source': "Antiope",
                'configurationItemCaptureTime': str(datetime.datetime.now()),
            }
            resource_item['awsRegion']                      = region
            resource_item['configuration']                  = instance
            if 'Tags' in instance:
                resource_item['tags']                       = parse_tags(instance['Tags'])
            resource_item['supplementaryConfiguration']     = {}
            resource_item['resourceId']                     = instance['InstanceId']
            resource_item['resourceCreationTime']           = instance['LaunchTime']
            resource_item['errors']                         = {}

            if instance['InstanceId'] in instance_profiles:
                resource_item['supplementaryConfiguration']['IamInstanceProfileAssociation'] = instance_profiles[instance['InstanceId']]

            save_resource_to_s3(INSTANCE_RESOURCE_PATH, resource_item['resourceId'], resource_item)


def process_securitygroups(target_account, ec2_client, region):

    sec_groups = get_all_securitygroups(ec2_client)
    logger.info(
        f"Found {len(sec_groups)} security groups for {target_account.account_id} in {region}"
    )

    # dump info about instances to S3 as json
    for sec_group in sec_groups:

        resource_item = {
            'awsAccountId': target_account.account_id,
            'awsAccountName': target_account.account_name,
            'resourceType': "AWS::EC2::SecurityGroup",
            'source': "Antiope",
            'configurationItemCaptureTime': str(datetime.datetime.now()),
        }
        resource_item['awsRegion']                      = region
        resource_item['configuration']                  = sec_group
        if 'Tags' in sec_group:
            resource_item['tags']                       = parse_tags(sec_group['Tags'])
        resource_item['supplementaryConfiguration']     = {}
        resource_item['resourceId']                     = sec_group['GroupId']
        resource_item['errors']                         = {}
        save_resource_to_s3(SG_RESOURCE_PATH, resource_item['resourceId'], resource_item)


def get_instance_profiles(ec2_client):
    assoc = []
    response = ec2_client.describe_iam_instance_profile_associations()
    while 'NextToken' in response:
        assoc += response['IamInstanceProfileAssociations']
        response = ec2_client.describe_iam_instance_profile_associations(NextToken=response['NextToken'])
    assoc += response['IamInstanceProfileAssociations']

    return {a['InstanceId']: a for a in assoc}


def get_all_instances(ec2_client):
    output = []
    response = ec2_client.describe_instances()
    while 'NextToken' in response:
        output += response['Reservations']
        response = ec2_client.describe_instances(NextToken=response['NextToken'])
    output += response['Reservations']
    return(output)


def get_all_securitygroups(ec2_client):
    output = []
    response = ec2_client.describe_security_groups()
    while 'NextToken' in response:
        output += response['SecurityGroups']
        response = ec2_client.describe_security_groups(NextToken=response['NextToken'])
    output += response['SecurityGroups']
    return(output)
