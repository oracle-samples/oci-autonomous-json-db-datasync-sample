# Copyright (c)  2022,  Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.import io
import base64
import datetime
import io
import json
import logging
import os
import random
import string
from zipfile import ZipFile

import cx_Oracle
import oci
from fdk import response


def get_dbwallet_from_autonomousdb():
	try:
		dbwalletzip_location = "/tmp/dbwallet.zip"

		ajd_client = oci.database.DatabaseClient(config={}, signer=signer)
		ajd_wallet_pwd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))  # random string
		# the wallet password is for creation of the jks
		ajd_wallet_details = oci.database.models.GenerateAutonomousDatabaseWalletDetails(password=ajd_wallet_pwd)
		# Get the AJD wallet zip file
		obj = ajd_client.generate_autonomous_database_wallet(ajd_ocid, ajd_wallet_details)
		# write the DB wallet zip to dbwalletzip_location
		with open(dbwalletzip_location, 'w+b') as f:
			for chunk in obj.data.raw.stream(1024 * 1024, decode_content=False):
				f.write(chunk)
		# extract the zip to dbwallet_dir
		with ZipFile(dbwalletzip_location, 'r') as wallet_zip:
			wallet_zip.extractall(dbwallet_dir)
	except Exception as ex:
		logging.getLogger().error(ex)
		raise


# This method is to get the secret content stored in vault using the secret name
def get_secret_from_vault(vault_secret_name):
	try:
		# get the secret client
		client = oci.secrets.SecretsClient({}, signer=signer)

		# Read the secret content
		secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,
														  vault_id=vault_ocid).data.secret_bundle_content.content
		decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
		return decrypted_secret_content

	except Exception as ex:
		logging.getLogger().error(ex)
		raise


#
# Function Instantiation code
#
try:

	signer = oci.auth.signers.get_resource_principals_signer()
	if os.getenv("TNS_ADMIN") is not None:
		dbwallet_dir = os.getenv('TNS_ADMIN')
	else:
		raise ValueError("ERROR: TNS_ADMIN entry missing in Docker File")

	if os.getenv("VAULT_OCID") is not None:
		vault_ocid = os.getenv("VAULT_OCID")
	else:
		raise ValueError("ERROR: Missing configuration key VAULT_OCID")
	if os.getenv("VAULT_KEY_OCID") is not None:
		vault_key_ocid = os.getenv("VAULT_KEY_OCID")
	else:
		raise ValueError("ERROR: Missing configuration key VAULT_KEY_OCID")

	if os.getenv("VAULT_COMPARTMENT_OCID") is not None:
		vault_compartment_ocid = os.getenv("VAULT_COMPARTMENT_OCID")
	else:
		raise ValueError("ERROR: Missing configuration key VAULT_COMPARTMENT_OCID")

	if os.getenv("AJD_SCHEMA_NAME") is not None:
		dbuser = os.getenv("AJD_SCHEMA_NAME")
	else:
		raise ValueError("ERROR: Missing configuration key AJD_SCHEMA_NAME")

	if os.getenv("AJD_SERVICE_NAME") is not None:
		dbsvc = os.getenv("AJD_SERVICE_NAME")
	else:
		raise ValueError("ERROR: Missing configuration key AJD_SERVICE_NAME")
	if os.getenv("AJD_OCID") is not None:
		ajd_ocid = os.getenv("AJD_OCID")
	else:
		raise ValueError("ERROR: Missing configuration key AJD_OCID")

	get_dbwallet_from_autonomousdb()

	# Update SQLNET.ORA file present in the dbwallet_dir by replacing
	# the WALLET_LOCATION parameter to point to the path of dbwallet_dir
	with open(dbwallet_dir + '/sqlnet.ora') as orig_sqlnetora:
		new_text = orig_sqlnetora.read().replace('DIRECTORY=\"?/network/admin\"',
												 'DIRECTORY=\"{}\"'.format(dbwallet_dir))
	with open(dbwallet_dir + '/sqlnet.ora', "w") as new_sqlnetora:
		new_sqlnetora.write(new_text)

	# Get database password from vault
	dbpwd = get_secret_from_vault('db_pwd')
	# create a DB pool

	dbpool = cx_Oracle.SessionPool(dbuser, dbpwd, dbsvc, min=1, max=1, encoding="UTF-8", nencoding="UTF-8")

except Exception as e:
	logging.getLogger().error(e)
	raise


#
# Function Handler
#
def handler(ctx, data: io.BytesIO = None):
	logging.getLogger().info("Inside handler method")
	try:
		payload_bytes = data.getvalue()
		if payload_bytes == b'':
			raise KeyError('No keys in payload')

		payload = json.loads(payload_bytes)
		# Update the payload with new key and values.
		payload["status"] = "not_processed"
		payload["createdDate"] = str(datetime.datetime.now().isoformat())
		# Read the authorization token from the request header
		auth_token = ctx.Headers().get("authorization")
		if "vaultSecretName" in payload:
			vault_secret_name = payload["vaultSecretName"]
		else:
			raise KeyError('Check if key vaultSecretName is set.')
		# Check if a secret with name as vault_secret_name already present in Vault.
		# If it is not present, create a new secret for storing authorization token.

		if not is_secret_in_vault(vault_secret_name):
			create_secret_in_vault(auth_token, vault_secret_name)
	except Exception as ex:
		logging.getLogger().error(ex)
		return response.Response(
			ctx,
			response_data="Processing failed due to " + str(ex),
			status_code=500
		)
	try:
		with dbpool.acquire() as dbconnection:
			dbconnection.autocommit = True

			soda = dbconnection.getSodaDatabase()
			# Open the Collection datasync_collection, if its already present in database
			# Else create a new collection
			collection = soda.openCollection("datasync_collection")
			if collection is None:
				collection = soda.createCollection("datasync_collection")
			# insert the payload to the collection
			collection.insertOne(payload)

	except Exception as ex1:
		logging.getLogger().error(ex1)
		return response.Response(
			ctx,
			response_data="Processing failed due to " + str(ex1),
			status_code=500
		)
	return response.Response(
		ctx,
		response_data="success"
	)


# Create a new secret in vault
def create_secret_in_vault(
		auth_token,
		vault_secret_name):
	logging.getLogger().info("Inside create_secret_in_vault method")
	try:
		vault_client = oci.vault.VaultsClient({}, signer=signer)

		secret_content_details = oci.vault.models.Base64SecretContentDetails(
			content_type=oci.vault.models.SecretContentDetails.CONTENT_TYPE_BASE64,
			name=vault_secret_name,
			stage="CURRENT",
			content=base64.b64encode(auth_token.encode('ascii')).decode("ascii"))
		secrets_details = oci.vault.models.CreateSecretDetails(compartment_id=vault_compartment_ocid,
															   secret_content=secret_content_details,
															   secret_name=vault_secret_name,
															   vault_id=vault_ocid,
															   key_id=vault_key_ocid)

		vault_client.create_secret(secrets_details)
	except Exception as ex:
		logging.getLogger().error("Failed to create the secret content due to exception. " + str(ex))
		raise


# Check if the secret is already present in vault
def is_secret_in_vault(vault_secret_name):
	logging.getLogger().info("Inside is_secret_in_vault method")
	try:
		vault_client = oci.vault.VaultsClient({}, signer=signer)

		list_secrets_response = vault_client.list_secrets(
			compartment_id=vault_compartment_ocid,
			name=vault_secret_name,
			vault_id=vault_ocid,
			lifecycle_state="ACTIVE")
		data = list_secrets_response.data

		if len(data) == 0:
			logging.getLogger().info("Secret not found in vault")
			return False
	except Exception as ex:
		logging.getLogger().error(
			"Failed to check if the secret is already present in Vault due to exception. " + str(ex))
		raise
	return True
