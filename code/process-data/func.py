# Copyright (c)  2022,  Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
import base64
import io
import json
import logging
import os
import random
import string
from urllib.parse import urlparse
from zipfile import ZipFile

import cx_Oracle
import oci
import requests
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
	RETRY_PATH = "/jsondb/process/retry"
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
	try:

		requesturl = ctx.RequestURL()
		parsed_url = urlparse(requesturl)
		# Get the path of the request URL to identify if the call is for retry
		path_param = parsed_url.path

		payload_bytes = data.getvalue()
		payload = json.loads(payload_bytes)

		if payload_bytes == b'':
			raise KeyError('No keys in payload')
		# Check if no_of_records_to_process is >0
		no_of_records_to_process = int(payload["no_of_records_to_process"])
		if no_of_records_to_process <= 0:
			raise ValueError('no_of_records_to_process must be greater than 0')
		# If the Function call is for retry, get additional keys from payload
		if path_param == RETRY_PATH:
			retry_limit = int(payload["retry_limit"])
			retry_codes = payload["retry_codes"]

	except Exception as ex1:
		logging.getLogger().error(ex1)

		if path_param == RETRY_PATH:
			message = "Missing keys- Check if no_of_records_to_process, retry_codes,retry_limit are set correctly"
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
			if path_param == RETRY_PATH:
				# Filter the records with status as failed and with status_code matching the retry codes specified in payload
				qbe = {'$query': {'status': {'$eq': 'failed'}, 'status_code': {'$in': retry_codes.split(',')}},
					   '$orderby': [
						   {'path': 'createdDate', 'datatype': 'timestamp'}]}
			else:
				# Filter the records with status as not_processed
				qbe = {'$query': {'status': {'$eq': 'not_processed'}},
					   '$orderby': [
						   {'path': 'createdDate', 'datatype': 'timestamp'}]}

			total_count = 0
			sucess_count = 0
			failed_count = 0
			skipped_count = 0
			# Total number of records returned by filter
			num_docs = collection.find().filter(qbe).count()
			# Loop through the filtered records
			for doc in collection.find().filter(qbe).limit(no_of_records_to_process).getDocuments():
				try:
					content = doc.getContent()
					is_processed = True

					if path_param == RETRY_PATH:
						# Check how many times retrial has happened for the selected record
						if "retry_attempts" in content:
							# If the retrial count of the record is less than specified limit, continue processing
							if int(content["retry_attempts"]) < retry_limit:
								content["retry_attempts"] = int(content["retry_attempts"]) + 1
								process(content)
							else:
								logging.getLogger().info('no of trials exceeded')
								is_processed = False
								# Count the no of records of skipped for processing  since record has reached the retry limit.
								skipped_count = skipped_count + 1
						# set the key retry_attempts in JSON to 1, if this is first retry attempt
						else:
							content["retry_attempts"] = 1
							process(content)
					else:
						process(content)

					# Replace the content with new content which has status_code and status
					if is_processed:
						collection.find().key(doc.key).replaceOne(content)
						if content['status'] == "success":
							sucess_count = sucess_count + 1
						elif content['status'] == "failed":
							failed_count = failed_count + 1
					total_count = total_count + 1
				except Exception as ex3:
					logging.getLogger().error(
						"Exception occured during the processing of " + str(doc.key) + "due to " + str(ex3))

			# Check if there are more records to process
			if num_docs <= no_of_records_to_process:
				has_next = "false"
			else:
				has_next = "true"

	except Exception as ex2:
		logging.getLogger().error(ex2)

		return response.Response(
			ctx,
			response_data="Failed in completing the request due to " + str(ex2),
			status_code=500
		)
	# Return the result of processing
	return response.Response(
		ctx,
		response_data='{"total_processed_records":' + str(total_count) + ',"success_count":' + str(
			sucess_count) + ',"failure_count":' + str(failed_count) + ',"skipped_count":' + str(
			skipped_count) + ',"has_next:"' + has_next + '"}'
	)


# This method is used to process the document in the collection
def process(content):
	# extract the json payload key values
	try:
		vault_secret_name = content["vaultSecretName"]
		target_rest_api = content["targetRestApi"]
		target_rest_api_operation = content["targetRestApiOperation"]
		target_rest_api_payload = content["targetRestApiPayload"]

	except Exception as ex3:
		logging.getLogger().error(ex3)
		content['status'] = 'failed'
		content['status_code'] = 500
		content[
			'failure_reason'] = 'Check if the payload contains vaultSecretName,targetRestApi,targetRestApiOperation,' \
								'targetRestApiPayload '
		return
	try:
		# Get the security token for API call rom vault
		auth_token = get_secret_from_vault(vault_secret_name)
		if "targetRestApiHeaders" in content:
			target_rest_api_headers = content["targetRestApiHeaders"]
		# Merge the authorization header with any other headers already present

		target_rest_api_headers.update({'Authorization': auth_token})

		if target_rest_api_operation == 'POST':

			api_call_response = requests.post(target_rest_api, data=json.dumps(target_rest_api_payload),
											  headers=target_rest_api_headers)
		elif target_rest_api_operation == 'PUT':

			api_call_response = requests.put(target_rest_api, data=json.dumps(target_rest_api_payload),
											 headers=target_rest_api_headers)
		elif target_rest_api_operation == 'DELETE':

			api_call_response = requests.delete(target_rest_api, data=json.dumps(target_rest_api_payload),
												headers=target_rest_api_headers)
		else:
			logging.getLogger().info("incorrect REST API method. Method should be either POST, PUT or DELETE")
			content['status'] = 'failed'
			content['status_code'] = 500
			content['failure_reason'] = "incorrect REST API method. Method should be either POST, PUT or DELETE"
			return

		if api_call_response.ok:
			content['status'] = 'success'
		else:

			content['status'] = 'failed'
			content['failure_reason'] = api_call_response.text

		content['status_code'] = api_call_response.status_code

	except Exception as ex4:
		logging.getLogger().error(ex4)
		content['status'] = 'failed'
		content['status_code'] = 500
		content['failure_reason'] = 'unexpected error. ' + str(ex4)
