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
	try:
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
	except Exception as e:
		logging.getLogger().error(e)
		raise


def get_secret_from_vault(vault_secret_name):
	try:
		signer = oci.auth.signers.get_resource_principals_signer()

		client = oci.secrets.SecretsClient({}, signer=signer)

		secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,
														  vault_id=vault_ocid).data.secret_bundle_content.content
		decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
		return decrypted_secret_content

	except Exception as e:
		logging.getLogger().error(e)
		raise


#
# Instantiation code: executed once when the function container is initialized
#
try:
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
		new_text = orig_sqlnetora.read().replace('DIRECTORY=\"?/network/admin\"',
												 'DIRECTORY=\"{}\"'.format(dbwallet_dir))
	with open(dbwallet_dir + '/sqlnet.ora', "w") as new_sqlnetora:
		new_sqlnetora.write(new_text)
	dbpwd = get_secret_from_vault('db_pwd')
	logging.getLogger().info('dbpwd =', dbpwd)
	dbpool = cx_Oracle.SessionPool(dbuser, dbpwd, dbsvc, min=1, max=1, encoding="UTF-8", nencoding="UTF-8")

except Exception as e:
	logging.getLogger().error(e)
	raise


#
# Function Handler: executed every time the function is invoked
#
def handler(ctx, data: io.BytesIO = None):
	try:

		requesturl = ctx.RequestURL()
		parsed_url = urlparse(requesturl)
		path_param = parsed_url.path
		logging.getLogger().info("path_param", path_param)
		payload_bytes = data.getvalue()
		payload = json.loads(payload_bytes)

		if payload_bytes == b'':
			raise KeyError('No keys in payload')
		no_of_records_to_process = int(payload["no_of_records_to_process"])
		if no_of_records_to_process <= 0:
			raise ValueError('no_of_records_to_process must be greater than 0')
		if path_param == '/jsondb/process/retry':
			no_of_times_to_retry = int(payload["no_of_times_to_retry"])
			retry_codes = payload["retry_codes"]

	except Exception as e:
		logging.getLogger().error(e)

		if path_param == '/jsondb/process/retry':
			message = "Missing keys- Check if no_of_records_to_process, retry_codes,no_of_times_to_retry are set correctly"
		else:
			message = "Missing keys- Check if no_of_records_to_process is set correctly"
		return response.Response(
			ctx,
			response_data=message,
			status_code=500
		)

	try:
		with dbpool.acquire() as dbconnection:
			dbconnection.autocommit = True

			soda = dbconnection.getSodaDatabase()
			collection = soda.openCollection("datasync_collection")
			# Check if it is a retry call
			if path_param == '/jsondb/process/retry':
				logging.getLogger().info("inside retry**")

				qbe = {'$query': {'status': {'$eq': 'failed'}, 'status_code': {'$in': retry_codes.split(',')}},
					   '$orderby': [
						   {'path': 'createdDate', 'datatype': 'datetime', 'order': 'asc'}]}
			else:
				qbe = {'$query': {'status': {'$eq': 'not_processed'}},
					   '$orderby': [
						   {'path': 'createdDate', 'datatype': 'datetime', 'order': 'asc'}]}

			total_count = 0
			sucess_count = 0
			failed_count = 0
			retrial_count_reached = 0

			num_docs = collection.find().filter(qbe).count()
			logging.getLogger().info('num_docs', num_docs)
			for doc in collection.find().filter(qbe).limit(no_of_records_to_process).getDocuments():
				content = doc.getContent()
				is_processed = True

				if path_param == '/jsondb/process/retry':
					# Check how many times retrial has happened
					if "retrial_count" in content:
						if int(content["retrial_count"]) < no_of_times_to_retry:
							content["retrial_count"] = int(content["retrial_count"]) + 1
							process(content)
						else:
							logging.getLogger().info('no of trials exceeded')
							is_processed = False
							retrial_count_reached = retrial_count_reached + 1
					else:
						content["retrial_count"] = 1
						process(content)
				else:
					process(content)

				# Replace the content with new content having status_code and status
				if is_processed == True:
					collection.find().key(doc.key).replaceOne(content)
					if content['status'] == "success":
						sucess_count = sucess_count + 1
					elif content['status'] == "failed":
						failed_count = failed_count + 1
				total_count = total_count + 1
				if num_docs <= no_of_records_to_process:
					has_next = "false"
				else:
					has_next = "true"
	except Exception as e:
		logging.getLogger().error(e)

		return response.Response(
			ctx,
			response_data="Failed in completing the request due to " + str(e),
			status_code=500
		)

	return response.Response(
		ctx,
		response_data='{"total_processed_records":' + str(total_count) + ',"success_count":' + str(
			sucess_count) + ',"failure_count":' + str(failed_count) + ',"retrial_count_reached":' + str(
			retrial_count_reached) + ',"has_next:"' + has_next + '"}'
	)


def process(content):
	logging.getLogger().info("inside process call")
	try:
		vault_secret_name = content["vaultSecretName"]
		target_rest_api = content["targetRestApi"]
		target_rest_api_operation = content["targetRestApiOperation"]
		target_rest_api_payload = content["targetRestApiPayload"]

	except Exception as e:
		logging.getLogger().error(e)
		content['status'] = 'failed'
		content['status_code'] = 500
		content[
			'failure_reason'] = 'Check if the payload contains vaultSecretName,targetRestApi,targetRestApiOperation,targetRestApiPayload'
		return
	try:
		auth_token = get_secret_from_vault(vault_secret_name)
		if "targetRestApiHeaders" in content:
			target_rest_api_headers = content["targetRestApiHeaders"]
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
		content['status_code'] = 500
		content['failure_reason'] = 'unexpected error {0}', e
