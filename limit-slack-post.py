from __future__ import print_function

import boto3
import json
import logging
import os
import json
from dateutil import parser

from base64 import b64decode
from urllib2 import Request, urlopen, URLError, HTTPError


if not 'kmsEncryptedHookUrl' in os.environ.keys() or  not 'slackChannel' in os.environ.keys() or not 'slackUser' in os.environ.keys():
    print ("Environment variables not defined.  Need 'kmsEncryptedHookUrl', 'slackChannel' and 'slackUser' ")
    exit(1)

# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slackChannel']
SLACK_USER = os.environ['slackUser']
if 'post_start' in os.environ.keys():
    POST_START=os.environ['post_start']
else:
    POST_START=10

if 'post_stop' in os.environ.keys():
    POST_STOP=os.environ['post_stop']
else:
    POST_STOP=17

HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext']


logger = logging.getLogger()
logger.setLevel(logging.INFO)

## no slack messages on Sat/Sun
def slacktime(timestamp):
    msg_hour = parser.parse(timestamp).hour
    logger.info ("Hour: " + str(msg_hour))
    return (msg_hour >= POST_START and msg_hour <= POST_STOP )

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = event['Records'][0]['Sns']['Message']
    timestamp = event['Records'][0]['Sns']['Timestamp']

    if slacktime(timestamp) is False:
        logger.info("Current time falls outside of Slack posting hours")
        return

    logger.info("URL: %s,  Channel: %s" % (HOOK_URL,SLACK_CHANNEL))

    slack_message = {
        'channel':  SLACK_CHANNEL,
        'username': SLACK_USER,
        'text': "%s" % message,
        'icon_emoji': ":a-w-s:"
    }

    req = Request(HOOK_URL, json.dumps(slack_message))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
