
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

FUNC_PATH = "lambda/function"
LAYER_PATH = "lambda/layer"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:
        target_account = AWSAccount(message['account_id'])
        for r in target_account.get_regions():
            discover_lambdas(target_account, r)
            discover_lambda_layer(target_account, r)

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


def discover_lambdas(target_account, region):
    '''Iterate across all regions to discover Lambdas'''

    lambdas = []
    client = target_account.get_client('lambda', region=region)
    response = client.list_functions()
    while 'NextMarker' in response:  # Gotta Catch 'em all!
        lambdas += response['Functions']
        response = client.list_functions(Marker=response['NextMarker'])
    lambdas += response['Functions']

    for l in lambdas:
        process_lambda(client, l, target_account, region)


def process_lambda(client, mylambda, target_account, region):
    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': "AWS::Lambda::Function",
        'source': "Antiope",
        'configurationItemCaptureTime': str(datetime.datetime.now()),
    }
    resource_item['awsRegion']                      = region
    resource_item['configuration']                  = mylambda
    if 'tags' in mylambda:
        resource_item['tags']                       = parse_tags(mylambda['tags'])
    resource_item['supplementaryConfiguration']     = {}
    resource_item[
        'resourceId'
    ] = f"""{target_account.account_id}-{region}-{mylambda['FunctionName'].replace("/", "-")}"""
    resource_item['resourceName']                   = mylambda['FunctionName']
    resource_item['ARN']                            = mylambda['FunctionArn']
    resource_item['errors']                         = {}

    try:
        response = client.get_policy(FunctionName=mylambda['FunctionArn'])
        if 'Policy' in response:
            resource_item['supplementaryConfiguration']['Policy']    = json.loads(response['Policy'])
    except ClientError as e:
        message = f"Error getting the Policy for function {mylambda['FunctionName']} in {region} for {target_account.account_name}: {e}"
        resource_item['errors']['Policy'] = message
        logger.warning(message)

    save_resource_to_s3(FUNC_PATH, resource_item['resourceId'], resource_item)


def discover_lambda_layer(target_account, region):
    '''Iterate across all regions to discover Lambdas'''
    try:
        layers = []
        client = target_account.get_client('lambda', region=region)
        response = client.list_layers()
        while 'NextMarker' in response:  # Gotta Catch 'em all!
            layers += response['Layers']
            response = client.list_layers(Marker=response['NextMarker'])
        layers += response['Layers']

        for l in layers:
            process_layer(client, l, target_account, region)
    except AttributeError as e:
        import botocore
        logger.error(f"Unable to inventory Lambda Layers - Lambda Boto3 doesn't support yet. Boto3: {boto3.__version__} botocore: {botocore.__version__}")
        return()


def process_layer(client, layer, target_account, region):
    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': "AWS::Lambda::Layer",
        'source': "Antiope",
        'configurationItemCaptureTime': str(datetime.datetime.now()),
    }
    resource_item['awsRegion']                      = region
    resource_item['configuration']                  = layer
    if 'tags' in layer:
        resource_item['tags']                       = parse_tags(layer['tags'])
    resource_item['supplementaryConfiguration']     = {}
    resource_item[
        'resourceId'
    ] = f"""{target_account.account_id}-{region}-{layer['LayerName'].replace("/", "-")}"""
    resource_item['resourceName']                   = layer['LayerName']
    resource_item['ARN']                            = layer['LayerArn']
    resource_item['errors']                         = {}

    try:
        resource_item['supplementaryConfiguration']['LayerVersions'] = []
        response = client.list_layer_versions(LayerName=layer['LayerName'], MaxItems=50)
        for version in response['LayerVersions']:
            version['Policy'] = client.get_layer_version_policy(LayerName=layer['LayerName'], VersionNumber=version['Version'])
            resource_item['supplementaryConfiguration']['LayerVersions'].append(version)
    except ClientError as e:
        message = f"Error getting the Policy for layer {layer['LayerName']} in {region} for {target_account.account_name}: {e}"
        resource_item['errors']['LayerVersions'] = message
        logger.warning(message)

    save_resource_to_s3(LAYER_PATH, resource_item['resourceId'], resource_item)
