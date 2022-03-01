import io
import json
import os
import random
import string
import logging
from zipfile import ZipFile

import cx_Oracle
import oci
import requests
from fdk import response
import base64


def get_dbwallet_from_autonomousdb():
	signer = oci.auth.signers.get_resource_principals_signer()  # authentication based on instance principal
	atp_client = oci.database.DatabaseClient(config={}, signer=signer)
	atp_wallet_pwd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))  # random string
	# the wallet password is only used for creation of the Java jks files, which aren't used by cx_Oracle so the value is not important
	atp_wallet_details = oci.database.models.GenerateAutonomousDatabaseWalletDetails(password=atp_wallet_pwd)
	logging.getLogger().info(atp_wallet_details)
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


#
# Instantiation code: executed once when the function container is initialized
#

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
	logging.getLogger().info('INFO: inside handler')
	try:
		with dbpool.acquire() as dbconnection:
			dbconnection.autocommit = True

			soda = dbconnection.getSodaDatabase()
			collection = soda.openCollection("datasync_collection")

			retry_codes = [503, 400, 401]

			qbe = {'$query': {'status': {'$eq': 'failed'}, 'status_code': {'$in': retry_codes}},
				   '$orderby': [{'path': 'targetRestApiPayload.created_date', 'datatype': 'datetime', 'order': 'asc'}]}
			logging.getLogger().info("qbe", qbe)
			total_count = 0
			sucess_count = 0
			failed_count = 0
			has_next = "true"
			num_docs = collection.find().filter(qbe).count
			for doc in collection.find().filter(qbe).limit(5).getDocuments():
				content = doc.getContent()

				logging.getLogger().info(content["vaultSecretName"] + ",", "key:", doc.key)
				process(content)
				logging.getLogger().info("processed content**", content)
				collection.find().key(doc.key).replaceOne(content)
				total_count = total_count + 1
				if content['status'] == "success":
					sucess_count = sucess_count + 1
				elif content['status'] == "failed":
					failed_count = failed_count + 1

			if total_count < 5 or num_docs == 0:
				has_next = "false"
			else:
				has_next = "true"

	except Exception as e:
		logging.getLogger().error(e)
		failed_count = failed_count + 1

	return response.Response(
		ctx,
		response_data='{"total_processed_records":' + str(total_count) + ',"success_count":' + str(
			sucess_count) + ',"failure_count":' + str(failed_count) + ',"has_next:"' + has_next + '"}'
	)


def process(content):
	logging.getLogger().info("inside process call")
	try:
		vault_secret_name = content["vaultSecretName"]
		target_rest_api = content["targetRestApi"]
		target_rest_api_operation = content["targetRestApiOperation"]
		target_rest_api_payload = content["targetRestApiPayload"]
		target_rest_api_headers = content["targetRestApiHeaders"]
		auth_token = get_secret_from_vault(vault_secret_name)
		# Merge two headers
		target_rest_api_headers.update({'Authorization': auth_token})

		if target_rest_api_operation == 'POST':
			logging.getLogger().info("inside POST call")

			api_call_response = requests.post(target_rest_api, data=json.dumps(target_rest_api_payload),
											  headers=target_rest_api_headers)
		elif target_rest_api_operation == 'PUT':
			logging.getLogger().info("inside PUT call")
			api_call_response = requests.put(target_rest_api, data=json.dumps(target_rest_api_payload),
											 headers=target_rest_api_headers)
		elif target_rest_api_operation == 'DELETE':
			logging.getLogger().info("inside DELETE call")
			api_call_response = requests.delete(target_rest_api, data=json.dumps(target_rest_api_payload),
												headers=target_rest_api_headers)
		else:
			logging.getLogger().info("incorrect REST API method. Method should be either POST, PUT or DELETE")
			return
		logging.getLogger().info(api_call_response.text)
		logging.getLogger().info(api_call_response.status_code)

		logging.getLogger().info("failure reason is", api_call_response.reason)
		if api_call_response.ok:
			content['status'] = 'success'
		else:

			content['status'] = 'failed'
			content['failure_reason'] = api_call_response.text

		content['status_code'] = api_call_response.status_code
	except Exception as e:
		logging.getLogger().error(e)

		content['status'] = 'failed'
		content['failure_reason'] = e
		process_status = "failed"
	return content
