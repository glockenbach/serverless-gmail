import glockenbach.commons as commons
import logging

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger('shovel')
logger.setLevel(commons.get_env_log_level(default=logging.INFO))


def get_matching_destination(forward_rules: dict, destinations: list) -> str:
    for destination in destinations:
        if destination in forward_rules.keys():
            return [destination, forward_rules[destination]]


def main(event, context):
    from boto3 import client as boto_client
    from email import message_from_bytes as email_message_from_bytes
    from json import loads as json_loads
    from re import sub as re_sub

    logger.debug(f'Event: \n{event}')

    email_bucket = commons.get_env_str('email_bucket')
    email_bucket_prefix = commons.get_env_str('email_bucket_prefix')
    email_forward_rules = json_loads(
        commons.get_env_str('email_forward_rules'))

    logger.debug(f'Rules: \n{email_forward_rules}')
    for record in event.get('Records', []):
        if 'aws:ses' == record['eventSource']:
            source = record['ses']['mail']['source']
            target = record['ses']['mail']['destination']
            subject = record['ses']['mail']['commonHeaders']['subject']

            logger.debug(f'Found email from {source} to {target}')
            rule, destination = get_matching_destination(
                email_forward_rules, target)

            if not destination:
                logger.info(f'No rules matching for: {target}')
                continue

            s3 = boto_client('s3')
            ses = boto_client('ses')

            message_id = record['ses']['mail']['messageId']
            key = f'{email_bucket_prefix}/{message_id}' if email_bucket_prefix else message_id

            s3_object = s3.get_object(Bucket=email_bucket, Key=key)
            logger.debug(f'S3Object: \n{s3_object}')
            s3_object_body = s3_object['Body']
            s3_object_meta = s3_object['Metadata']
            content_length = int(s3_object_meta.get(
                'x-amz-unencrypted-content-length', 0)
                or s3_object.get('ContentLength', 0)
            )

            if content_length and content_length > 10485760:
                logger.info(f'The size {content_length} is too large. \
                            Notify to source: {source}')
                ses.send_email(
                    Source=rule,
                    Destination={
                        'ToAddresses': [source]
                    },
                    Message={
                        'Subject': {
                            'Data': subject,
                            'Charset': 'UTF-8'
                        },
                        'Body': {
                            'Text': {
                                'Data': 'Your email was rejected due to the maximum 10mb size constraint',
                                'Charset': 'UTF-8'
                            }
                        }
                    },
                    ReplyToAddresses=[rule],
                    ReturnPath=rule
                )
                continue

            if 'kms' == s3_object_meta.get('x-amz-wrap-alg'):
                from Cryptodome.Cipher import AES
                from base64 import b64decode as base64_b64decode

                logger.debug(f'Decrypt Body')
                kms = boto_client('kms')
                envelope_iv = base64_b64decode(s3_object_meta['x-amz-iv'])

                decrypted_envelope_key = kms.decrypt(
                    CiphertextBlob=base64_b64decode(
                        s3_object_meta['x-amz-key-v2']
                    ),
                    EncryptionContext=json_loads(
                        s3_object_meta['x-amz-matdesc']
                    )
                )

                decryptor = AES.new(
                    decrypted_envelope_key['Plaintext'],
                    AES.MODE_GCM,
                    envelope_iv
                )

                decrypted_body = b''
                while True:
                    chunk = s3_object_body.read(16*1024)
                    if len(chunk) == 0:
                        break
                    decrypted_body += decryptor.decrypt(chunk)

                decrypted_body_array = bytearray(decrypted_body)
                raw_mail = decrypted_body_array[:content_length or None]
            else:
                logger.debug(f'Read Raw Body')
                raw_mail = s3_object['Body'].read()

            logger.info(f'Shovel email to <{destination}>')
            email_message = email_message_from_bytes(raw_mail)
            original_from = email_message['From']

            del email_message['DKIM-Signature']
            del email_message['Sender']
            del email_message['Reply-To']
            email_message['Reply-To'] = original_from
            del email_message['Return-Path']
            email_message['Return-Path'] = rule
            del email_message['From']
            email_message['From'] = re_sub(
                r'\<.*?\>', f'<{rule}>', original_from)

            ses.send_raw_email(
                Destinations=[destination],
                RawMessage=dict(
                    Data=email_message.as_bytes()
                )
            )
