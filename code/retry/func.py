import io
import json
import cx_Oracle
import oci
import os
from zipfile import ZipFile
import string
import random
from timeit import default_timer as timer
import requests
import base64
import logging
from fdk import response


def get_dbwallet_from_autonomousdb():
    signer = oci.auth.signers.get_resource_principals_signer()  # authentication based on instance principal
    atp_client = oci.database.DatabaseClient(config={}, signer=signer)
    atp_wallet_pwd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))  # random string
    # the wallet password is only used for creation of the Java jks files, which aren't used by cx_Oracle so the value is not important
    atp_wallet_details = oci.database.models.GenerateAutonomousDatabaseWalletDetails(password=atp_wallet_pwd)
    print(atp_wallet_details, flush=True)
    obj = atp_client.generate_autonomous_database_wallet(adb_ocid, atp_wallet_details)
    with open(dbwalletzip_location, 'w+b') as f:
        for chunk in obj.data.raw.stream(1024 * 1024, decode_content=False):
            f.write(chunk)
    with ZipFile(dbwalletzip_location, 'r') as zipObj:
        zipObj.extractall(dbwallet_dir)

#
# Instantiation code: executed once when the function container is initialized
#

vault_ocid = os.getenv("vault_ocid")
vault_key_ocid= os.getenv("vault_key_ocid")
vault_compartment_ocid = os.getenv("vault_compartment_ocid")
vault_key_ocid = os.getenv("vault_key_ocid")
if os.getenv("DBUSER") != None:
    dbuser = os.getenv("DBUSER")
else:
    raise ValueError("ERROR: Missing configuration key DBUSER")
if os.getenv("DBPWD_CYPHER") != None:
    dbpwd_cypher = dbpwd = os.getenv(
        "DBPWD_CYPHER")  # The decryption of the db password using OCI KMS would have to be done, however it is not addressed here
else:
    raise ValueError("ERROR: Missing configuration key DBPWD_CYPHER")
if os.getenv("DBSVC") != None:
    dbsvc = os.getenv("DBSVC")
else:
    raise ValueError("ERROR: Missing configuration key DBSVC")
adb_ocid = os.getenv("ADB_OCID")

# Download the DB Wallet
dbwalletzip_location = "/tmp/dbwallet1.zip"
dbwallet_dir = os.getenv("TNS_ADMIN")

# if (len(os.listdir(dbwallet_dir))==0):
# start_wallet = timer()
get_dbwallet_from_autonomousdb()
# end_wallet = timer()
# print('INFO: DB wallet downloaded from Autonomous DB in {} sec'.format(end_wallet - start_wallet), flush=True)
print('INFO: DB wallet dir content =', dbwallet_dir, os.listdir(dbwallet_dir), flush=True)

# Update SQLNET.ORA
with open(dbwallet_dir + '/sqlnet.ora') as orig_sqlnetora:
    newText = orig_sqlnetora.read().replace('DIRECTORY=\"?/network/admin\"', 'DIRECTORY=\"{}\"'.format(dbwallet_dir))
with open(dbwallet_dir + '/sqlnet.ora', "w") as new_sqlnetora:
    new_sqlnetora.write(newText)

dbpool = cx_Oracle.SessionPool(dbuser, dbpwd, dbsvc, min=1, max=1, encoding="UTF-8", nencoding="UTF-8")


#
# Function Handler: executed every time the function is invoked
#
def handler(ctx, data: io.BytesIO = None):
    
    print('INFO: inside handler', flush=True)
    try:      
        with dbpool.acquire() as dbconnection:
            dbconnection.autocommit = True
           
            soda = dbconnection.getSodaDatabase()           
            collection = soda.openCollection("mycollection")        
            
            retry_codes= [503, 400, 401]

            qbe = {'$query' : { 'status': {'$eq': 'failed'} ,'status_code':{'$in': retry_codes }},'$orderby' :[{ 'path' : 'targetRestApiPayload.created_date', 'datatype' : 'datetime', 'order' : 'asc' }]}
            print("qbe",qbe,flush=True)
            total_count=0
            sucess_count=0
            failed_count=0
            hasNext="true" 
            num_docs=collection.find().filter(qbe).count
            for doc in collection.find().filter(qbe).limit(5).getDocuments():
                content = doc.getContent()
                
                print(content["vaultSecretName"] + ",", "key:", doc.key)
                process(content)
                print("processed content**",content)
                collection.find().key(doc.key).replaceOne(content)    
                total_count=total_count+1  
                if  content['status'] == "success":
                    sucess_count=sucess_count+1
                elif content['status'] == "failed":
                    failed_count=failed_count+1
                
            if  total_count <5 or num_docs==0:
                hasNext="false" 
            else:
                hasNext="true"          
       
    except Exception as e:
        print(e, flush=True)
        failed_count=failed_count+1
        
    return response.Response(
            ctx,
            response_data='{"total_processed_records":'+str(total_count)+',"success_count":'+str(sucess_count)+',"failure_count":'+str(failed_count)+',"hasNext:"'+hasNext+'"}'
        )  
        
       
   
def process(content):
    print("inside process call", flush=True)
    try:
        vault_secret_name = content["vaultSecretName"]            
        target_rest_api = content["targetRestApi"]
        target_rest_api_operation = content["targetRestApiOperation"]
        target_rest_api_payload = content["targetRestApiPayload"]
        target_rest_api_headers = content["targetRestApiHeaders"]
        auth_token=get_secret_from_vault(vault_secret_name,vault_ocid)
        # Merge two headers
        target_rest_api_headers.update({'Authorization': auth_token})
        
        if (target_rest_api_operation=='POST'):
            print("inside POST call", flush=True)
           
            api_call_response = requests.post(target_rest_api, data = json.dumps(target_rest_api_payload),headers=target_rest_api_headers)
        elif (target_rest_api_operation=='PUT'):
            print("inside PUT call", flush=True)
            api_call_response = requests.put(target_rest_api, data = json.dumps(target_rest_api_payload),headers=target_rest_api_headers)
        elif (target_rest_api_operation=='DELETE'):
            print("inside DELETE call", flush=True)
            api_call_response = requests.delete(target_rest_api, data = json.dumps(target_rest_api_payload),headers=target_rest_api_headers)

        print(api_call_response.text, flush=True)
        print(api_call_response.status_code, flush=True)
        print("failure reason is",api_call_response.reason, flush=True)
        if (api_call_response.ok):
            content['status']='success';  
        else:         
             
            content['status']='failed';
            content['failure_reason']=api_call_response.text;
        
        content['status_code']=api_call_response.status_code;
    
    except Exception as e:
        print(e, flush=True)
            
        content['status']='failed';
        content['failure_reason']=e
        process_status="failed"
    return content
def get_secret_from_vault(vault_secret_name,vault_ocid):
        
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        # secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,vault_id=vault_ocid).data.secret_bundle_content.content.encode('utf-8')
        secret_content = client.get_secret_bundle_by_name(secret_name=vault_secret_name,vault_id=vault_ocid).data.secret_bundle_content.content
       
        # decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    return  secret_content

