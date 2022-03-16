import json
import cx_Oracle
import oci
import os
from zipfile import ZipFile
import string
import random
import io
import requests
import base64
import logging
from fdk import response
from urllib.parse import urlparse, parse_qs


def get_dbwallet_from_autonomousdb():
	signer = oci.auth.signers.get_resource_principals_signer()  # authentication based on instance principal
	atp_client = oci.database.DatabaseClient(config={}, signer=signer)
	atp_wallet_pwd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))  # random string
	# the wallet password is  for creation of the  jks files,  so the value is not important
	atp_wallet_details = oci.database.models.GenerateAutonomousDatabaseWalletDetails(password=atp_wallet_pwd)

	obj = atp_client.generate_autonomous_database_wallet(adb_ocid, atp_wallet_details)
	with open(dbwalletzip_location, 'w+b') as f:
		for chunk in obj.data.raw.stream(1024 * 1024, decode_content=False):
			f.write(chunk)
	with ZipFile(dbwalletzip_location, 'r') as zipObj:
		zipObj.extractall(dbwallet_dir)


def get_secret_from_vault(vault_secret_name):
	signer = oci.auth.signers.get_resource_principals_signer()

	client = oci.secrets.SecretsClient({}, signer=signer)

	secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,
													  vault_id=vault_ocid).data.secret_bundle_content.content
	decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
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

if os.getenv("retry_codes") is not None:
	retry_codes = os.getenv("retry_codes")
else:
	raise ValueError("ERROR: Missing configuration key retry_codes")

# Download the DB Wallet
dbwalletzip_location = "/tmp/dbwallet.zip"
dbwallet_dir = os.getenv('TNS_ADMIN')

get_dbwallet_from_autonomousdb()

logging.getLogger().info('DB wallet dir content =', dbwallet_dir, os.listdir(dbwallet_dir))
# Update SQLNET.ORA
with open(dbwallet_dir + '/sqlnet.ora') as orig_sqlnetora:
	new_text = orig_sqlnetora.read().replace('DIRECTORY=\"?/network/admin\"', 'DIRECTORY=\"{}\"'.format(dbwallet_dir))
with open(dbwallet_dir + '/sqlnet.ora', "w") as new_sqlnetora:
	new_sqlnetora.write(new_text)
dbpwd = get_secret_from_vault('db_pwd')
logging.getLogger().info('dbpwd =', dbpwd)
dbpool = cx_Oracle.SessionPool(dbuser, dbpwd, dbsvc, min=1, max=1, encoding="UTF-8", nencoding="UTF-8")


#
# Function Handler: executed every time the function is invoked
#
def handler(ctx, data: io.BytesIO = None):
	try:

		requesturl = ctx.RequestURL()
		parsed_url = urlparse(requesturl)
		path_param = parsed_url.path
		with dbpool.acquire() as dbconnection:
			dbconnection.autocommit = True

			soda = dbconnection.getSodaDatabase()
			collection = soda.openCollection("datasync_collection")
			# Check if it is a retry call
			if path_param == '/jsondb/process/retry':

				qbe = {'$query': {'status': {'$eq': 'failed'}, 'status_code': {'$in': retry_codes.split(',')}},
					   '$orderby': [
						   {'path': 'targetRestApiPayload.created_date', 'datatype': 'datetime', 'order': 'asc'}]}
			else:
				qbe = {'$query': {'status': {'$eq': 'not_processed'}},
					   '$orderby': [
						   {'path': 'targetRestApiPayload.created_date', 'datatype': 'datetime', 'order': 'asc'}]}

			total_count = 0
			sucess_count = 0
			failed_count = 0

			num_docs = collection.find().filter(qbe).count()
			logging.getLogger().info('num_docs', num_docs)
			for doc in collection.find().filter(qbe).limit(5).getDocuments():
				content = doc.getContent()
				process(content)
				if path_param == '/jsondb/process/retry':
					retrial_count = content["retrial_count"]
					if retrial_count is None:
						content["retrial_count"] = 1
					else:
						content["retrial_count"] = int(content["retrial_count"]) + 1

				# Replace the content with new content having status_code and status
				collection.find().key(doc.key).replaceOne(content)
				if content['status'] == "success":
					sucess_count = sucess_count + 1
				elif content['status'] == "failed":
					failed_count = failed_count + 1
				total_count = total_count + 1
	except Exception as e:
		logging.getLogger().error(e)
		failed_count = failed_count + 1
		total_count = total_count + 1

	if num_docs < 5:
		has_next = "false"
		logging.getLogger().info("replaced content**#####4")
	else:
		has_next = "true"
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
			content['status'] = 'failed'
			content['failure_reason'] = "incorrect REST API method. Method should be either POST, PUT or DELETE"
			return

		if api_call_response.ok:
			content['status'] = 'success'
		else:

			content['status'] = 'failed'
			content['failure_reason'] = api_call_response.text

		content['status_code'] = api_call_response.status_code

	except Exception as e:
		logging.getLogger().error(e)
		content['status'] = 'failed'
		content['failure_reason'] = 'unexpected error'
