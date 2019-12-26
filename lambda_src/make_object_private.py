# -*- coding: utf-8 -*-
"""
.. module: make_object_private
    :Actions: if object ACL is public, makes them private
    :copyright: (c) 2020 Mystique.,
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

import json
import logging

import boto3
from botocore.exceptions import ClientError

__author__      = 'Mystique'
__email__       = 'miztiik@github'
__version__     = '0.0.1'
__status__      = 'production'


class global_args:
    """
    Global statics
    """
    OWNER                       = 'Mystique'
    ENVIRONMENT                 = 'production'
    MODULE_NAME                 = 'make_object_private'
    LOG_LEVEL                   = logging.INFO


def set_logging(lv=global_args.LOG_LEVEL):
    '''
    Helper to enable logging
    '''
    logging.basicConfig(level=lv)
    logger = logging.getLogger()
    logger.setLevel(lv)
    return logger

# Initialize Logger
logger = set_logging(logging.INFO)

############### END OF HELPERS ###############

def make_obj_private(bucket_name, obj_key):
    """
    Make object in bucket private
    """
    resp = {'status': False}
    client = boto3.client('s3')
    try:
        m_resp = client.put_object_acl(Bucket=bucket_name, Key=obj_key, ACL="private")
        logger.info(f"Object:{obj_key} in Bucket:{bucket_name} is marked private")
        if m_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
            resp['status'] = True
            resp['acl_remediated'] = True
    except ClientError as e:
        logger.error("Unable to mark object:{obj_key} private")
        logger.error(f"ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def lambda_handler(event, context):
    """
    # Helper to make object private
    """
    logger.info(f'Event:{event}')
    resp = {'status': False}
    EVENT_TYPE = 'PutObjectAcl'
    # Match Event Type
    if 'obj_key' in event and 'bucket_name' in event:
        if event['obj_key'] and event['bucket_name']:
            resp['bucket_name'] = event.get('bucket_name')
            resp['obj_key'] = event.get('obj_key')
            m_resp = make_obj_private(event['bucket_name'], event['obj_key'])
            resp['acl_remediated'] = m_resp.get('acl_remediated')
            resp['status'] = True

    # we are unable to determine, Prepare message for notification
    if not m_resp.get('status'):
        resp['sns_message'] = (
            f"Object:{resp['obj_key']} in bucket:{resp['bucket_name']} is private."
            f"Unable to remediate object Acl"
            f"ERROR:{str(m_resp.get('error_message'))}"
            )
        logger.error(f"ERROR:{m_resp.get('error_message')}")
        resp['error_message'] = m_resp.get('error_message')
    return resp

if __name__ == '__main__':
    lambda_handler({}, {})
