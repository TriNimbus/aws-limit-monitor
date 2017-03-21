from __future__ import print_function

import boto3
import json
import logging
import os
import json
from datetime import datetime

from base64 import b64decode
from urllib2 import Request, urlopen, URLError, HTTPError


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
    POST_STOP=15

HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext']


logger = logging.getLogger()
logger.setLevel(logging.INFO)

## no slack messages on Sat/Sun
def slacktime():
    currHour = datetime.now().hour
    currDay = datetime.today().weekday()
    return currHour >= POST_START and currHour <= POST_STOP and currDay < 5

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = event['Records'][0]['Sns']['Message']

    if slacktime() is False:
        logger.info("Current time falls outside of Slack posting hours")
        return

    logger.info("URL: %s,  Channel: %s" % (HOOK_URL,SLACK_CHANNEL))

    slack_message = {
        'channel':  SLACK_CHANNEL,
        'username': SLACK_USER,
        'text': "%s" % message,
        'icon_emoji': ":aws:"
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
