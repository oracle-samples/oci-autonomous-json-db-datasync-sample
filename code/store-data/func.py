import io
import json
import cx_Oracle
import oci
import os
from zipfile import ZipFile
import string
import random

import base64
from timeit import default_timer as timer

import logging
from fdk import response


def get_dbwallet_from_autonomousdb():
	signer = oci.auth.signers.get_resource_principals_signer()  # authentication based on instance principal
	atp_client = oci.database.DatabaseClient(config={}, signer=signer)
	atp_wallet_pwd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))  # random string
	# the wallet password is for creation of the jks
	atp_wallet_details = oci.database.models.GenerateAutonomousDatabaseWalletDetails(password=atp_wallet_pwd)

	obj = atp_client.generate_autonomous_database_wallet(adb_ocid, atp_wallet_details)
	with open(dbwalletzip_location, 'w+b') as f:
		for chunk in obj.data.raw.stream(1024 * 1024, decode_content=False):
			f.write(chunk)
	with ZipFile(dbwalletzip_location, 'r') as zipObj:
		zipObj.extractall(dbwallet_dir)


def get_secret_from_vault(vault_secret_name):
	signer = oci.auth.signers.get_resource_principals_signer()
	try:
		client = oci.secrets.SecretsClient({}, signer=signer)

		secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,
														  vault_id=vault_ocid).data.secret_bundle_content.content
		decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")

	except Exception as ex:
		logging.getLogger().error("Failed to retrieve the secret content", ex)
		raise
	return decrypted_secret_content


# Instantiation code: executed once when the function container is initialized
if os.getenv("vault_ocid") is not None:
	vault_ocid = os.getenv("vault_ocid")
else:
	raise ValueError("ERROR: Missing configuration key vault_ocid")
if os.getenv("vault_key_ocid") is not None:
	vault_key_ocid = os.getenv("vault_key_ocid")
else:
	raise ValueError("ERROR: Missing configuration key vault_key_ocid")

if os.getenv("vault_compartment_ocid") is not None:
	vault_compartment_ocid = os.getenv("vault_compartment_ocid")
else:
	raise ValueError("ERROR: Missing configuration key vault_compartment_ocid")

if os.getenv("DBUSER") is not None:
	dbuser = os.getenv("DBUSER")
else:
	raise ValueError("ERROR: Missing configuration key DBUSER")

if os.getenv("DBSVC") is not None:
	dbsvc = os.getenv("DBSVC")
else:
	raise ValueError("ERROR: Missing configuration key DBSVC")
if os.getenv("ADB_OCID") is not None:
	adb_ocid = os.getenv("ADB_OCID")
else:
	raise ValueError("ERROR: Missing configuration key ADB_OCID")

# Download the DB Wallet
dbwalletzip_location = "/tmp/dbwallet.zip"
dbwallet_dir = os.getenv('TNS_ADMIN')

get_dbwallet_from_autonomousdb()

# Update SQLNET.ORA
with open(dbwallet_dir + '/sqlnet.ora') as orig_sqlnetora:
	new_text = orig_sqlnetora.read().replace('DIRECTORY=\"?/network/admin\"', 'DIRECTORY=\"{}\"'.format(dbwallet_dir))
with open(dbwallet_dir + '/sqlnet.ora', "w") as new_sqlnetora:
	new_sqlnetora.write(new_text)
dbpwd = get_secret_from_vault('db_pwd')

dbpool = cx_Oracle.SessionPool(dbuser, dbpwd, dbsvc, min=1, max=1, encoding="UTF-8", nencoding="UTF-8")


#
# Function Handler
#
def handler(ctx, data: io.BytesIO = None):
	try:
		payload_bytes = data.getvalue()
		if payload_bytes == b'':
			raise KeyError('No keys in payload')

		payload = json.loads(payload_bytes)
		payload["status"] = "not_processed"
		auth_token = ctx.Headers().get("authorization")

		logging.getLogger().info("auth_token", auth_token)

		vault_secret_name = payload["vaultSecretName"]
		if not is_secret_in_vault(vault_secret_name):
			create_secret_in_vault(auth_token, vault_secret_name)

		with dbpool.acquire() as dbconnection:
			dbconnection.autocommit = True

			# create a new SODA collection; this will open an existing collection, if
			# the name is already in use
			start = timer()
			soda = dbconnection.getSodaDatabase()

			collection = soda.openCollection("datasync_collection")
			if collection is None:
				collection = soda.createCollection("datasync_collection")
			# insert a document into the collection; for the common case of a JSON
			# document
			collection.insertOneAndGet(payload)
			end = timer()
			print('INFO: inserted in {} sec'.format(end - start), flush=True)
		return response.Response(
			ctx,
			response_data="success" + format(end - start)
		)
	except Exception as e:
		logging.getLogger().error(e)
		return response.Response(
			ctx,
			response_data="failed"
		)


# Create a new secret in vault
def create_secret_in_vault(
		auth_token,
		vault_secret_name):
	logging.getLogger().info("INSIDE  create_secret_in_vault")
	signer = oci.auth.signers.get_resource_principals_signer()
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
		logging.getLogger().error("Failed to create the secret content", ex)
		raise


# Check if the secret is already present in vault
def is_secret_in_vault(vault_secret_name):
	logging.getLogger().info("INSIDE  is_secret_in_vault")

	signer = oci.auth.signers.get_resource_principals_signer()
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
		logging.getLogger().error("Failed to retrieve the secret content", ex)
		raise
	return True
