import base64
import logging
import os
import string
import time
from datetime import datetime
from random import *
import hashlib

from flask import Response, request, json
from twilio.rest import Client

import kyc.config as config
from helpers.shufti_kyc import get_shufti_data_by_reference, delete_shufti_data_by_reference, \
    extract_data_from_callback, prepare_data_for_signing, get_shufti_access_token
from helpers.sign_data import sign
from kyc import app, signing_key, nacl, db, conn, send_email
from kyc.database import update_user_identity_data, insert_access_token_attempt, get_attempts_by_hash_spi

logging.getLogger("werkzeug").setLevel(level=logging.ERROR)

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)

handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s][%(filename)s:%(lineno)s - %(funcName)s()]: %(message)s",
                              "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)

logger.addHandler(handler)


@app.route("/verification/send-email", methods=['POST'])
def verify_email_handler():
    body = request.get_json()
    logger.debug('body %s', body)

    user_id = body.get('user_id').lower()
    email = body.get('email')
    redirect_url = config.REDIRECT_URL + "/verifyemail"
    public_key = body.get('public_key')
    resend = body.get('resend')
    letters = string.ascii_uppercase + string.ascii_lowercase + string.ascii_letters
    verification_code = ''.join(choice(letters) for i in range(randint(64, 128)))
    user = db.getUserByName(conn, user_id)

    logger.debug("verification_code: %s", verification_code)

    union = "?"

    if union in redirect_url:
        union = "&"

    url = "{}{}userId={}&verificationCode={}".format(redirect_url, union, user_id, verification_code)
    logger.debug("url: %s", url)

    html = "Hi {} <br><br> You have just created a ThreeFold Connect account.<br> On behalf of the ThreeFold Connect team, we hereby provide a link to verify your email address. When you click on this link, you will be taken to a page confirming your address is verified.<br> Without this verification, not all features will be available.<br> <a href=""{}>Verify my email address</a><br><br> Thanks,<br>OpenKYC Team".format(
        user_id, url)

    try:
        if not user:
            logger.debug("not user")
            db.insert_user(conn, user_id, email, verification_code, 0, public_key, "")
        else:
            logger.debug("updating using verficiation code, because we already have an entry.")
            db.update_user_verification_code(conn, user_id, verification_code, email)
            url = "{}{}userId={}&verificationCode={}".format(redirect_url, union, user_id, verification_code)
            logger.debug("url: %s", url)

        logger.debug("Sending email to %s ..." % email)
        send_email(email, html)
        print("verification_code")
        print(verification_code)

        return Response("Mail sent")
    except Exception as exception:
        logger.debug("Exception")
        logger.error(exception)
        return Response("Something went wrong", status=500)


@app.route("/verification/verify-email", methods=['POST'])
def verify_handler():
    body = request.get_json()
    userid = body.get('user_id').lower()
    verification_code = body.get('verification_code')
    user = db.getUserByName(conn, userid)

    if user:
        if verification_code == user[2]:
            data = bytes('{ "email": "' + user[1] + '", "identifier": "' + user[0] + '" }', encoding='utf8')
            signed_email_identifier = signing_key.sign(data, encoder=nacl.encoding.Base64Encoder)

            if signed_email_identifier:
                db.update_user(conn, "UPDATE users SET signed_email_identifier = ? WHERE user_id = ?",
                               signed_email_identifier.decode("utf-8"), user[0])
                logger.debug("Successfully verified userid %s", user[0])
                return signed_email_identifier
            else:
                return Response('Something went wrong.', status=403)
        else:
            logger.debug("Attempted to verify userid %s with an incorrect verification_code %s", userid,
                         verification_code)
            return Response('Something went wrong.', status=403)
    else:
        logger.debug("No open verifications found for userid %s", userid)
        return Response('Something went wrong.', status=403)


@app.route("/verification/send-sms", methods=['POST'])
def send_sms_handler():
    body = request.get_json()
    logger.debug('body %s', body)

    user_id = body.get('user_id').lower().removesuffix('.3bot')
    number = body.get('number')
    redirect_url = config.REDIRECT_URL + "/verifysms"
    public_key = body.get('public_key')

    letters = string.ascii_uppercase + string.ascii_lowercase + string.ascii_letters
    verification_code = ''.join(choice(letters) for i in range(randint(64, 128)))
    user = db.getPhoneUserByName(conn, user_id)

    union = "?"

    if union in redirect_url:
        union = "&"

    url = "{}{}userId={}&verificationCode={}".format(redirect_url, union, user_id, verification_code)
    logger.debug("url: %s", url)

    text = """Hello {},

If you requested a phone verification for ThreeFold Connect, please click the following link.

{}

Thanks,
OpenKYC Team""".format(
        user_id, url)

    try:
        if not user:
            logger.debug("not user")
            db.insert_phone_user(conn, user_id, number, verification_code, 0, public_key, "")
        else:
            logger.debug("updating using verficiation code, because we already have an entry.")
            db.update_phone_user_verification_code(conn, user_id, verification_code)

        logger.debug("Sending sms...")
        db.update_phone_user_verification_code(conn, user_id, verification_code)

        client = Client(os.environ['TWILIO_ACCOUNT_SID'], os.environ['TWILIO_AUTH_TOKEN'])

        message = client.messages.create(messaging_service_sid=os.environ['MESSAGING_SERVICE_SID'], body=text,
                                         to=number)

        db.update_phone_user_phone_number(conn, user_id, number)

        return Response("SMS sent")
    except Exception as exception:
        logger.debug("Exception")
        logger.error(exception)
        return Response("Something went wrong", status=500)


@app.route("/verification/verify-sms", methods=['POST'])
def verify_sms_handler():
    body = request.get_json()
    userid = body.get('user_id').lower()
    verification_code = body.get('verification_code')
    user = db.getPhoneUserByName(conn, userid)

    logger.debug(user)

    if user:
        if verification_code == user[2]:
            data = bytes('{ "phone": "' + user[1] + '", "identifier": "' + user[0] + '" }', encoding='utf8')
            signed_phone_identifier = signing_key.sign(data, encoder=nacl.encoding.Base64Encoder)

            if signed_phone_identifier:
                db.update_user(conn, "UPDATE phone_users SET signed_phone_identifier = ? WHERE user_id = ?",
                               signed_phone_identifier.decode("utf-8"), user[0])
                logger.debug("Successfully verified userid %s", user[0])
                return signed_phone_identifier
            else:
                return Response('Something went wrong.', status=403)
        else:
            logger.debug("Attempted to verify userid %s with an incorrect verification_code %s", userid,
                         verification_code)
            return Response('Something went wrong.', status=403)
    else:
        logger.debug("No open verifications found for userid %s", userid)
        return Response('Something went wrong.', status=403)


@app.route('/verification/shufti-access-token', methods=['POST'])
def get_shufti_token():
    REQUEST_LIMIT = int(os.environ['SHUFTI_REQUEST_LIMIT'])
    body = request.get_json()

    try:
        public_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        verify_key = nacl.signing.VerifyKey(public_key, encoder=nacl.encoding.HexEncoder)
        spi_decoded = base64.b64decode(body.get('signedPhoneIdentifier'))
        spi = verify_key.verify(spi_decoded)

        logger.debug("Successfully verified signature: %s", spi.decode('utf-8'))

    except Exception as e:
        logger.error('Error in Shufti-Access-Token')
        logger.error("Couldn't sign the SPI")
        print(e)
        return Response('We were not able to sign the SPI', 500)

    try:
        hashed_spi = hashlib.sha256(str.encode(body.get('signedPhoneIdentifier')))
        hex_dig = hashed_spi.hexdigest()

        attempts = get_attempts_by_hash_spi(conn, hex_dig)
        if len(attempts) >= REQUEST_LIMIT:
            logger.debug('Daily limit of SPI has been exceed')
            return Response('Daily limit of SPI has been exceed', 403)

        insert_access_token_attempt(conn, hex_dig)

        access_token = get_shufti_access_token()
        if access_token is None:
            return Response('Access token could not be made', 500)

        return app.response_class(
            response=json.dumps(access_token),
            mimetype='application/json'
        )

    except Exception as e:
        logger.error('Error in Shufti-Access-Token')
        logger.error("Couldn't hash the SPI")
        print(e)
        return Response('Internal Server Error', 500)


@app.route("/verification/send-identity", methods=['POST'])
def get_verification_code_for_identity():
    body = request.get_json()
    logger.debug('POST Call on send-identity')
    logger.debug('Body: %s', body)

    user_id = body.get('user_id').lower()
    kyc_level = body.get('kycLevel')

    if int(kyc_level) < 2 or kyc_level is None:
        return Response("Only KYC level 2 is accepted.", status=403)

    public_key = body.get('public_key')
    letters = string.ascii_uppercase + string.ascii_lowercase + string.ascii_letters
    verification_code = ''.join(choice(letters) for i in range(randint(64, 128)))

    user = db.get_identity_user_by_name(conn, user_id)
    try:
        if not user:
            logger.debug("User %s is not found in the database" % user_id)
            db.insert_identity_user(conn, user_id, verification_code, 0, public_key, "", "", "", "", "")

        else:
            logger.debug("Updating using verification code, because we already have an entry.")
            db.update_identity_user_verification_code(conn, user_id, verification_code)

        db.update_identity_user_verification_code(conn, user_id, verification_code)

        data = {
            'user_id': user_id,
            'verification_code': verification_code
        }

        return app.response_class(
            response=json.dumps(data),
            mimetype='application/json'
        )

    except Exception as exception:
        logger.debug("Error in send-identity")
        logger.error(exception)
        return Response("Something went wrong", status=500)


@app.route("/verification/verify-identity", methods=['POST'])
def verify_identity_handler():
    logger.debug('POST Call on verify-identity')
    body = request.get_json()
    userid = body.get('user_id').lower()
    kyc_level = body.get('kycLevel')

    if int(kyc_level) < 2 or kyc_level is None:
        return Response("Only KYC level 2 is accepted.", status=403)

    reference = body.get('reference')
    user = db.get_identity_user_by_name(conn, userid)

    if user is None:
        return Response("User not found", 404)

    if reference != user[1]:
        return Response("Can't sign the identity since the verification code does not match", 400)

    try:
        shufti_data = get_shufti_data_by_reference(reference)
        extracted_data = extract_data_from_callback(shufti_data)
        prepared_data = prepare_data_for_signing(extracted_data, user)

        signed_identity_name_identifier = sign(prepared_data['name_data'])
        signed_identity_country_identifier = sign(prepared_data['country_data'])
        signed_identity_dob_identifier = sign(prepared_data['dob_data'])
        signed_identity_document_meta_data_identifier = sign(prepared_data['document_meta_data'])
        signed_identity_gender_identifier = sign(prepared_data['gender_data'])
        signed_identity_is_identified_identifier = sign(prepared_data['is_identified_data'])

        if signed_identity_name_identifier is None:
            return Response("Failed to sign the name data", 400)
        if signed_identity_country_identifier is None:
            return Response("Failed to sign the country data", 400)
        if signed_identity_dob_identifier is None:
            return Response("Failed to sign the dob data", 400)
        if signed_identity_document_meta_data_identifier is None:
            return Response("Failed to sign the document_meta_data data", 400)
        if signed_identity_gender_identifier is None:
            return Response("Failed to sign the gender data", 400)
        if signed_identity_is_identified_identifier is None:
            return Response("Failed to sign the is_identified data", 400)

        update_user_identity_data(conn, signed_identity_name_identifier, signed_identity_country_identifier,
                                  signed_identity_dob_identifier, signed_identity_document_meta_data_identifier,
                                  signed_identity_gender_identifier, user[0])

        logger.debug("Successfully verified identity for user %s", user[0])
        return Response('OK', 200)

    except Exception as e:
        logger.debug("Error in verify-identity")
        logger.error(e)
        return Response("Something went wrong", status=500)


@app.route("/verification/retrieve-sii/<userid>", methods=['GET'])
def get_signed_identity_identifier_handler(userid):
    userid = userid.lower()
    user = db.get_identity_user_by_name(conn, userid)

    if user is None:
        return Response("User was not found.", 404)

    signed_response = verify_signed_data(user[0], request.headers.get('Jimber-Authorization'),
                                         user[3], "get-identity-kyc-data-identifiers")

    if isinstance(signed_response, Response):
        logger.debug("Failed to verify")
        return signed_response

    try:
        signed_identity_name_identifier = user[4]
        signed_identity_country_identifier = user[5]
        signed_identity_dob_identifier = user[6]
        signed_identity_document_meta_identifier = user[7]
        signed_identity_gender_identifier = user[8]

        if signed_identity_name_identifier is None:
            return Response("signed_identity_name_identifier not found.", 404)

        if signed_identity_country_identifier is None:
            return Response("signed_identity_country_identifier not found.", 404)

        if signed_identity_dob_identifier is None:
            return Response("signed_identity_dob_identifier not found.", 404)

        if signed_identity_document_meta_identifier is None:
            return Response("signed_identity_document_meta_identifier not found.", 404)

        if signed_identity_gender_identifier is None:
            return Response("signed_identity_gender_identifier not found.", 404)

        logger.debug("We found an account: %s", user[0])
        logger.debug("Retrieved SII for %s", userid)

        db.delete_identity_user(conn, user[0])

        data = {
            "signed_identity_name_identifier": signed_identity_name_identifier.decode('utf-8'),
            "signed_identity_country_identifier": signed_identity_country_identifier.decode('utf-8'),
            "signed_identity_dob_identifier": signed_identity_dob_identifier.decode('utf-8'),
            "signed_identity_document_meta_identifier": signed_identity_document_meta_identifier.decode('utf-8'),
            "signed_identity_gender_identifier": signed_identity_gender_identifier.decode('utf-8')
        }

        response = app.response_class(
            response=json.dumps(data),
            mimetype='application/json'
        )

        return response

    except Exception as e:
        logger.debug("Error in retrieve SII")
        logger.error(e)
        return Response("Something went wrong", status=500)


@app.route("/verification/retrieve-sei/<userid>", methods=['GET'])
def get_signed_email_identifier_handler(userid):
    userid = userid.lower()
    user = db.getUserByName(conn, userid)

    if user is None:
        logger.debug("User was not found.")
        return Response("User was not found.", status=404)

    signed_data_verification_response = verify_signed_data(user[0], request.headers.get('Jimber-Authorization'),
                                                           user[4], "get-signedemailidentifier")

    if (isinstance(signed_data_verification_response, Response)):
        logger.debug("response of verification is of instance Response, failed to verify.")
        return signed_data_verification_response

    if len(user) >= 5 and not user[5]:
        logger.debug("We found an old account: %s", user[0])

        if user[3] == 1:
            logger.debug("Old account was verified, creating signature.")

            data = bytes('{ "email": "' + user[1] + '", "identifier": "' + user[0] + '" }', encoding='utf8')
            signed_email_identifier = signing_key.sign(data, encoder=nacl.encoding.Base64Encoder)

            sei = {"signed_email_identifier": signed_email_identifier.decode("utf-8")}

            response = app.response_class(
                response=json.dumps(sei),
                mimetype='application/json'
            )

            logger.debug("SEI: %s", sei)
            return response

        else:
            logger.debug("Old account was not verified. User needs to resend the email.")
            return Response("something went wrong", status=404)

    if user[5]:
        logger.debug("We found an account: %s", user[0])
        logger.debug("Retrieved signed_email_identifier for %s", userid)

        db.delete_user(conn, user[0], user[1])

        data = {"signed_email_identifier": user[5]}

        logger.debug("data: %s", data)

        response = app.response_class(
            response=json.dumps(data),
            mimetype='application/json'
        )

        return response
    else:
        return Response("User not found in database.", status=404)


@app.route("/verification/retrieve-spi/<userid>", methods=['GET'])
def get_signed_phone_identifier_handler(userid):
    userid = userid.lower()
    user = db.getPhoneUserByName(conn, userid)

    if user is None:
        logger.debug("User was not found.")
        return Response("User was not found.", status=404)

    signed_data_verification_response = verify_signed_data(user[0], request.headers.get('Jimber-Authorization'),
                                                           user[4], "get-signedphoneidentifier")

    if isinstance(signed_data_verification_response, Response):
        logger.debug("response of verification is of instance Response, failed to verify.")
        return signed_data_verification_response

    if len(user) >= 5 and not user[5]:
        logger.debug("We found an old account: %s", user[0])

        if user[3] == 1:
            logger.debug("Old account was verified, creating signature.")

            data = bytes('{ "phone": "' + user[1] + '", "identifier": "' + user[0] + '" }', encoding='utf8')
            signed_phone_identifier = signing_key.sign(data, encoder=nacl.encoding.Base64Encoder)

            spi = {"signed_phone_identifier": signed_phone_identifier.decode("utf-8")}

            response = app.response_class(
                response=json.dumps(spi),
                mimetype='application/json'
            )

            logger.debug("SPI: %s", spi)
            return response

        else:
            logger.debug("Old account was not verified. User needs to resend the sms.")
            return Response("something went wrong", status=404)

    if user[5]:
        logger.debug("We found an account: %s", user[0])
        logger.debug("Retrieved signed_phone_identifier for %s", userid)

        db.delete_phone_user(conn, user[0], user[1])

        data = {"signed_phone_identifier": user[5]}

        logger.debug("data: %s", data)

        response = app.response_class(
            response=json.dumps(data),
            mimetype='application/json'
        )

        return response
    else:
        return Response("User not found in database.", status=404)


@app.route("/verification/public-key", methods=['GET'])
def public_key_handler():
    data = {"public_key": signing_key.verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode("utf8")}

    response = app.response_class(
        response=json.dumps(data),
        mimetype='application/json'
    )

    return response


@app.route("/verification/verify-sii", methods=['POST'])
def verification_identity_handler():
    try:
        body = request.get_json()
        public_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        verify_key = nacl.signing.VerifyKey(public_key, encoder=nacl.encoding.HexEncoder)

        signed_identity_name_identifier_decoded = base64.b64decode(body.get("signedIdentityNameIdentifier"))
        signed_identity_country_identifier_decoded = base64.b64decode(body.get("signedIdentityCountryIdentifier"))
        signed_identity_dob_identifier_decoded = base64.b64decode(body.get("signedIdentityDOBIdentifier"))
        signed_identity_document_meta_identifier_decoded = base64.b64decode(
            body.get("signedIdentityDocumentMetaIdentifier"))
        signed_identity_gender_identifier_decoded = base64.b64decode(body.get("signedIdentityGenderIdentifier"))

        signed_identity_name_identifier_verified = verify_key.verify(signed_identity_name_identifier_decoded)
        signed_identity_country_identifier_verified = verify_key.verify(signed_identity_country_identifier_decoded)
        signed_identity_dob_identifier_verified = verify_key.verify(signed_identity_dob_identifier_decoded)
        signed_identity_document_meta_identifier_verified = verify_key.verify(
            signed_identity_document_meta_identifier_decoded)
        signed_identity_gender_identifier_verified = verify_key.verify(signed_identity_gender_identifier_decoded)

        reference = body.get('reference')
        if reference is None:
            return Response("Couldn't delete the KYC data since the reference is not given", status=500)

        # delete_shufti_data_by_reference(reference)

        response_data = {
            'signedIdentityNameIdentifierVerified': signed_identity_name_identifier_verified.decode(
                'utf-8'),
            'signedIdentityCountryIdentifierVerified': signed_identity_country_identifier_verified.decode('utf-8'),
            'signedIdentityDOBIdentifierVerified': signed_identity_dob_identifier_verified.decode('utf-8'),
            'signedIdentityDocumentMetaIdentifierVerified': signed_identity_document_meta_identifier_verified.decode(
                'utf-8'),
            'signedIdentityGenderIdentifierVerified': signed_identity_gender_identifier_verified.decode('utf-8'),
        }

        response = app.response_class(
            response=json.dumps(response_data),
            mimetype='application/json'
        )

        return response

    except Exception as exception:
        logger.debug(exception)
        return Response("Invalid or corrupted signature", status=500)


# This function is only used to verify identifiers in the example login.
@app.route("/verification/verify-identity-identifier", methods=['POST'])
def verification_identity_specific_handler():
    try:
        identifier = request.args.get('identifier')
        body = request.get_json()

        public_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        verify_key = nacl.signing.VerifyKey(public_key, encoder=nacl.encoding.HexEncoder)

        signed_identity_identifier_decoded = base64.b64decode(body.get('identifier'))

        signed_identity_identifier_verified = verify_key.verify(signed_identity_identifier_decoded)

        response_data = {
            identifier: signed_identity_identifier_verified.decode(
                'utf-8'),
        }

        response = app.response_class(
            response=json.dumps(response_data),
            mimetype='application/json'
        )

        return response

    except Exception as exception:
        logger.debug(exception)
        return Response("Invalid or corrupted signature", status=500)

@app.route("/verification/verify-sei", methods=['POST'])
def verification_handler():
    try:
        body = request.get_json()
        public_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)

        verify_key = nacl.signing.VerifyKey(public_key, encoder=nacl.encoding.HexEncoder)

        sei_decoded = base64.b64decode(body.get("signedEmailIdentifier"))
        sei = verify_key.verify(sei_decoded)

        logger.debug("Successfully verified signature: %s", sei.decode('utf-8'))

        response = app.response_class(
            response=sei,
            mimetype='application/json'
        )

        return response

    except Exception as exception:
        logger.debug("Invalid or corrupted signature for sid: %s", body.get("signedEmailIdentifier"))
        return Response("Invalid or corrupted signature", status=500)


@app.route("/verification/verify-spi", methods=['POST'])
def verification_sms_handler():
    try:
        body = request.get_json()
        public_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)

        verify_key = nacl.signing.VerifyKey(public_key, encoder=nacl.encoding.HexEncoder)

        spi_decoded = base64.b64decode(body.get("signedPhoneIdentifier"))
        spi = verify_key.verify(spi_decoded)

        logger.debug("Successfully verified signature: %s", spi.decode('utf-8'))

        response = app.response_class(
            response=spi,
            mimetype='application/json'
        )

        return response
    except Exception as exception:
        logger.debug("Invalid or corrupted signature for sid: %s", body.get("signedPhoneIdentifier"))
        return Response("Invalid or corrupted signature", status=500)


def verify_signed_data(double_name, data, encoded_public_key, intention, expires_in=3600):
    if data is not None:
        decoded_data = base64.b64decode(data)

        bytes_data = bytes(decoded_data)

        public_key = base64.b64decode(encoded_public_key)
        verify_key = nacl.signing.VerifyKey(public_key.hex(), encoder=nacl.encoding.HexEncoder)

        verified_signed_data = verify_key.verify(bytes_data)

        if verified_signed_data:
            verified_signed_data = json.loads(verified_signed_data.decode("utf-8"))
            if (verified_signed_data["intention"] == intention):
                timestamp = verified_signed_data["timestamp"]
                readable_signed_timestamp = datetime.fromtimestamp(int(timestamp) / 1000)
                current_timestamp = time.time() * 1000
                readable_current_timestamp = datetime.fromtimestamp(int(current_timestamp / 1000))
                difference = (int(timestamp) - int(current_timestamp)) / 1000
                # All negative times are accepted, we should refactor this to take the timeout into account and the possibility that the users time is a bit wrong.
                if difference <= expires_in:
                    logger.debug("Jimber-Authorization-Header verified.")
                    return verified_signed_data
                else:
                    logger.debug("Timestamp was expired took %s instead of %s", difference, expires_in)
                    return Response("something went wrong", status=404)
            else:
                logger.debug("Wrong intention.")
                return Response("something went wrong", status=404)
        else:
            logger.debug("Jimber-Authorization-Header could not be verified.")
            return Response("something went wrong", status=404)
    else:
        logger.debug("No data to sign.")
        return Response("something went wrong", status=404)
