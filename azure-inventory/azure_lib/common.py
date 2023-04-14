import json
import os

import json


from msrestazure.azure_active_directory import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.consumption import ConsumptionManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.resource import ResourceManagementClient


import boto3
from botocore.exceptions import ClientError
from .subscription import AzureSubscription

import logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


def safe_dump_json(obj) -> dict:
    return {key: str(obj.__dict__[key]) for key in obj.__dict__.keys()}


def get_azure_creds(secret_name):
    """
    Get the azure service account key stored in AWS secrets manager.
    """

    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        logger.critical(f"Unable to get secret value for {secret_name}: {e}")
        return(None)
    else:
        if 'SecretString' in get_secret_value_response:
            secret_value = get_secret_value_response['SecretString']
        else:
            secret_value = get_secret_value_response['SecretBinary']

    try:
        return json.loads(secret_value)
    except Exception as e:
        logger.critical(f"Error during Credential and Service extraction: {e}")
        return(None)


def save_resource_to_s3(prefix, resource_id, resource):
    s3client = boto3.client('s3')
    object_key = f"Azure-Resources/{prefix}/{resource_id}.json"

    try:
        s3client.put_object(
            Body=json.dumps(resource, sort_keys=True, default=str, indent=2),
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='application/json',
            Key=object_key,
        )
    except ClientError as e:
        logger.error(f"Unable to save object {object_key}: {e}")


def return_azure_creds(app_id,key, tenant_id):
    return ServicePrincipalCredentials(
        client_id=app_id,
        secret=key,
        tenant=tenant_id
    )


def get_subcriptions(azure_creds):

    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    resource_client = SubscriptionClient(creds)

    collected_subs = []
    for subscription in resource_client.subscriptions.list():

        consumption_client = ConsumptionManagementClient(creds, subscription.subscription_id, base_url=None)
        sum = 0
        for uu in consumption_client.usage_details.list():
            sum += uu.pretax_cost

        subscription_dict = {"subscription_id": subscription.subscription_id, "display_name": subscription.display_name,
                             "cost": int(sum), "state": str(subscription.state)}


        collected_subs.append(subscription_dict)

    return collected_subs


def get_public_ips_of_subscription(azure_creds, subscription_id):
    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    network_management_client = NetworkManagementClient(creds, subscription_id)

    return [
        safe_dump_json(ip)
        for ip in network_management_client.public_ip_addresses.list_all()
    ]


def get_vms(azure_creds, subscription_id):

    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    compute_management_client = ComputeManagementClient(creds, subscription_id)

    return [
        safe_dump_json(m)
        for m in compute_management_client.virtual_machines.list_all()
    ]


def get_disks(azure_creds, subscription_id):
    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    compute_management_client = ComputeManagementClient(creds, subscription_id)
    
    return _generic_json_list_return(compute_management_client.disks.list())

def get_sql_servers(azure_creds, subscription_id):

    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])
    sql_server_resource_client = SqlManagementClient(creds, subscription_id)

    resource_source_client = ResourceManagementClient(creds,subscription_id)

    return _generic_json_list_return(sql_server_resource_client.servers.list())


def get_data_factories(azure_creds, subscription_id):

    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    data_factory_client = DataFactoryManagementClient(creds,subscription_id)

    return _generic_json_list_return(data_factory_client.factories.list())

def get_key_vaults(azure_creds, subscription_id):
    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    key_vault_client = KeyVaultManagementClient(creds, subscription_id)
    
    return _generic_json_list_return(key_vault_client.vaults.list())

def get_logic_apps(azure_creds, subscription_id):
    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    logic_app_client = LogicManagementClient(creds, subscription_id)

    return _generic_json_list_return(logic_app_client.list_operations())

    
def _generic_json_list_return(object_list) -> list:
    return [safe_dump_json(m) for m in object_list]
    

def get_storage_accounts(azure_creds, subscription_id):

    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    storage_client = StorageManagementClient(creds, subscription_id)

    return [safe_dump_json(ss) for ss in storage_client.storage_accounts.list()]

def get_web_sites(azure_creds, subscription_id):

    creds = return_azure_creds(azure_creds["application_id"], azure_creds["key"], azure_creds["tenant_id"])

    web_client = WebSiteManagementClient(creds, subscription_id)

    return [safe_dump_json(website) for website in web_client.web_apps.list()]
