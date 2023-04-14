
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

CONNECTION_PATH = "dx/connection"
VIF_PATH = "dx/vif"
GW_PATH = "dx/gw"

# These are NOT AWS Standard Types - DirectConnect is not provided by Config or Cloudformation, so I'm having to guess here.
CONNECTION_TYPE = "AWS::DX::DXCON"
VIF_TYPE = "AWS::DX::DXVIF"
GW_TYPE = "AWS::DX::DXGW"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:
        target_account = AWSAccount(message['account_id'])

        # DX Gateways are a global service. The same ones show up if I query for them in each region
        # Therefore, we query for them once, and decorate them with their VIFs as we find them in each region
        dx_gws = discover_gateways(target_account)

        for r in target_account.get_regions():
            discover_connections(target_account, r)
            dx_gws = discover_vifs(target_account, r, dx_gws)

        # Now save the gateways
        for gwid, resource_item in dx_gws.items():
            save_resource_to_s3(GW_PATH, resource_item['resourceId'], resource_item)

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


def discover_connections(target_account, region):
    '''Inventory all the Direct Connect Connections (ie, physical cross connects into AWS)'''

    dx_client = target_account.get_client('directconnect', region=region)
    response = dx_client.describe_connections()

    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': CONNECTION_TYPE,
        'source': "Antiope",
        'awsRegion': region,
    }
    for c in response['connections']:
        resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
        resource_item['configuration']                  = c
        resource_item['supplementaryConfiguration']     = {}
        resource_item['resourceId']                     = c['connectionId']
        resource_item['resourceName']                   = c['connectionName']
        resource_item['errors']                         = {}

        save_resource_to_s3(CONNECTION_PATH, resource_item['resourceId'], resource_item)


def discover_vifs(target_account, region, dx_gws):
    ''' Inventory all the Direct Connect Virtual Interfaces '''

    dx_client = target_account.get_client('directconnect', region=region)
    response = dx_client.describe_virtual_interfaces()

    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': VIF_TYPE,
        'source': "Antiope",
        'awsRegion': region,
    }
    for vif in response['virtualInterfaces']:
        print(f"Found VIF {vif['virtualInterfaceId']}")
        resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
        resource_item['configuration']                  = vif
        resource_item['supplementaryConfiguration']     = {}
        resource_item['resourceId']                     = vif['virtualInterfaceId']
        resource_item['resourceName']                   = vif['virtualInterfaceName']
        resource_item['errors']                         = {}
        # The same VIF ID will be discovered in the account with the DX Connection, and the account the DX is shared with.
        save_resource_to_s3(
            VIF_PATH,
            f"{resource_item['resourceId']}-{target_account.account_id}",
            resource_item,
        )

        if vif['ownerAccount'] != target_account.account_id:
            continue  # Don't marry DXGWs for the account that's sharing out the VIF.

        # We should decorate the dxgws with this regions discovered VIFs
        if 'directConnectGatewayId' in vif and vif['directConnectGatewayId'] != "":
            if vif['directConnectGatewayId'] in dx_gws:
                # The vif data structure contains region, so we don't need to add that here.
                dx_gws[vif['directConnectGatewayId']]['supplementaryConfiguration']['VirtualInterfaces'].append(vif)
            else:
                error_mesg = f"Found VIF {vif['virtualInterfaceId']} in {region} with a directConnectGatewayId of {vif['directConnectGatewayId']}, but no DXGW with that id exists"
                logger.critical(error_mesg)
                raise Exception(error_mesg)

    return(dx_gws)


def discover_gateways(target_account):
    ''' Inventory all the Direct Connect Gateways and any associated VGWs and attached VIFs '''

    output = {}

    dx_client = target_account.get_client('directconnect')
    response = dx_client.describe_direct_connect_gateways()

    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': GW_TYPE,
        'source': "Antiope",
    }
    for c in response['directConnectGateways']:
        resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
        resource_item['configuration']                  = c
        resource_item['supplementaryConfiguration']     = {}
        resource_item['resourceId']                     = c['directConnectGatewayId']
        resource_item['resourceName']                   = c['directConnectGatewayName']
        resource_item['errors']                         = {}

        # Prep the array that will hold any VIFs we discover attached to this gateway
        resource_item['supplementaryConfiguration']['VirtualInterfaces'] = []

        output[c['directConnectGatewayId']] = resource_item

    return(output)
