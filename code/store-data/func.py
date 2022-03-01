import io
import json
import cx_Oracle
import oci
import os
from zipfile import ZipFile
import string
import random

import base64

import logging
from fdk import response


def get_dbwallet_from_autonomousdb():
	signer = oci.auth.signers.get_resource_principals_signer()  # authentication based on instance principal
	atp_client = oci.database.DatabaseClient(config={}, signer=signer)
	atp_wallet_pwd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))  # random string
	# the wallet password is only used for creation of the Java jks files, which aren't used by cx_Oracle so the value
	# is not important
	atp_wallet_details = oci.database.models.GenerateAutonomousDatabaseWalletDetails(password=atp_wallet_pwd)
	logging.getLogger().info("AJD Wallet Details", atp_wallet_details)
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
		# secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,
		# vault_id=vault_ocid).data.secret_bundle_content.content.encode('utf-8')
		secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,
														  vault_id=vault_ocid).data.secret_bundle_content.content
		decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
		logging.getLogger().info("decrypted_secret_content", decrypted_secret_content)
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

logging.getLogger().info('DB wallet dir content =', dbwallet_dir, os.listdir(dbwallet_dir))
# Update SQLNET.ORA
with open(dbwallet_dir + '/sqlnet.ora') as orig_sqlnetora:
	newText = orig_sqlnetora.read().replace('DIRECTORY=\"?/network/admin\"', 'DIRECTORY=\"{}\"'.format(dbwallet_dir))
with open(dbwallet_dir + '/sqlnet.ora', "w") as new_sqlnetora:
	new_sqlnetora.write(newText)
dbpwd = get_secret_from_vault('db_pwd')

dbpool = cx_Oracle.SessionPool(dbuser, dbpwd, dbsvc, min=1, max=1, encoding="UTF-8", nencoding="UTF-8")


#
# Function Handler: executed every time the function is invoked
#
def handler(ctx, data: io.BytesIO = None):
	try:
		logging.getLogger().info("headers", ctx.Headers())

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
			soda = dbconnection.getSodaDatabase()

			collection = soda.openCollection("datasync_collection")
			if collection is None:
				collection = soda.createCollection("datasync_collection")
			# insert a document into the collection; for the common case of a JSON
			# document, the content can be a simple Python dictionary which will
			# internally be converted to a JSON document

			# "value must be a SODA document or a dictionary or list"
			returned_doc = collection.insertOneAndGet(payload)
			key = returned_doc.key
			logging.getLogger().info('The key of the new SODA document is: ', key)
			content = collection.find().key(key).getOne().getContent()
			logging.getLogger().info(content)

		return response.Response(
			ctx,
			response_data="success"
		)
	except Exception as e:
		logging.getLogger().error(e)
		return response.Response(
			ctx,
			response_data="failed"
		)


def create_secret_in_vault(
		auth_token,
		vault_secret_name):
	logging.getLogger().info("INSIDE  create_secret_in_vault")
	signer = oci.auth.signers.get_resource_principals_signer()
	try:
		vault_client = oci.vault.VaultsClient({}, signer=signer)

		create_secret_details = oci.vault.models.CreateSecretDetails(
			compartment_id=vault_compartment_ocid,
			key_id=vault_key_ocid,
			secret_content=oci.vault.models.Base64SecretContentDetails(
				content_type="BASE64",
				name=vault_secret_name,
				stage="CURRENT",
				content=auth_token),
			secret_name=vault_secret_name,
			vault_id=vault_ocid)
		vault_client.create_secret(create_secret_details)
	except Exception as ex:
		logging.getLogger().error("Failed to create the secret content", ex)
		raise


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
		logging.getLogger().info("the secret cotent is ", data)
		if len(data) == 0:
			logging.getLogger().info("Secret not found in vault")
			return False
	except Exception as ex:
		logging.getLogger().error("Failed to retrieve the secret content", ex)
		raise
	return True
