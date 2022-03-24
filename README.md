# Data Syncing using Oracle Cloud Infrastructure(OCI) - Autonomous JSON DB(AJD) based Pattern

## Introduction


There are many instances where there is a need for syncing data from source application/s to target application/s. 
A sample scenario is a custom mobile app/ web application developed to perform transactions on SaaS data. In this case, the mobile/web application fetches data from SaaS. User will perform transactions on  this data and those transactions  should be pushed to SaaS. Here source application is the custom mobile/web application and target application is SaaS. Another case could be the integration of external systems with SaaS, with a need to continuously send data from those external systems to SaaS.
Regardless of what the source or target application is, it is ideal to have a middle tier using Oracle Cloud Infrastructure (OCI) native services that handles the data flow due to a number of reasons —

1.	Reduced load on the source application in terms of data sync operations, retrials and error handling.
2.	Ability to persist data at middle tier and perform retrials on this data in case of failure.
3.	Ability to handle data sync from multiple source & target applications from a single middle tier.
4.	Ability to transform or filter messages at the middle tier before sending to target application.
5.	Easy monitoring/reporting of the data flow. 
6.	Ability to fire notifications in case of failures.
7.	Ability to have a consolidated view of the data sync activities and error cases.
8.	Ability to enable data syncing in a publish-subscribe asynchronous model. 
9.	Allow source application to continue with data syncing operation even if target application is down, say for maintenance. 
10.	Ability to use centralized metrics and logging features.
11.	Ability to scale the middle tier based on the data load and processing requirements. 



This solution shows how you can Oracle Cloud Infrastructure (OCI) cloud native services to build a serverless data syncing solution. There are various approaches to build a data sync middle tier using OCI. This one uses Autonomous JSON DB(AJD), API Gateway, Functions, Vault, OCI Registry.

Choosing OCI Cloud Native Services as middle tier has the following benefits,
1.	They are based on open source and standards.
2.	They have built-in management capabilities. So development teams can focus on building competitive features and spend less time installing, patching, and maintaining infrastructure.
3.	Availability of good pricing models.
4.	They are highly secure, scalable, durable and reliable.

## Services / libraries used in this sample


[Autonomous JSON DB](https://www.oracle.com/autonomous-database/)


Oracle Autonomous JSON Database is a cloud document database service that makes it simple to develop JSON-centric applications. Autonomous Database comes with several built-in features like Oracle Apex, Database Actions- View data using SQL, JSON, REST, DataModelers, Administration Tools etc.

The AJD used in this sample is named as _jsonDB_.


[SODA](https://docs.oracle.com/en/database/oracle/simple-oracle-document-access/)

This sample uses SODA APIs to access Autonomous JSON databse. SODA abstractions hide the complexities of SQL and client programming using

1. Collection
2. Document


**Collection**

A SODA collection is analogous to an Oracle Database table or view.  A document collection contains documents. 
Collections are persisted in an Oracle Database schema . A database schema is referred to as a SODA database.

In addition to its content, a document has other document components, including a unique identifier, called its key, a version, a media type (type of content), and the date and time that it was created and last modified. 

The key is typically assigned by SODA when a document is created. The other components are generated and maintained by SODA. 

**Document**

A SODA document is analogous to, a row of a database table or view. The row has one column for each document component: key, content, version, and so on.

SODA provides CRUD operations on documents. JSON documents can additionally be queried, using query-by-example (QBE) patterns, also known as filter specifications. A filter specification is itself a JSON object.

In this sample, a single collection is used, _DataSyncCollection_. This collection contains the json payload posted by the source application.


[Functions](https://www.oracle.com/cloud-native/functions/)

Functions are under an Application, _DataSyncWithJSONDB_ . It has the following configuration variables. 

![Application configuration variables]( /image/ApplicationConfiguration.png "Application configuration variables")

_AJD_SERVICE_NAME_ is the database service name.
_AJD_SCHEMA_NAME_ is the database schema/user to connect to.

In addition to these, configuration contains OCIDs of various services.


2 Functions are used in this pattern. They are python Functions and uses [SODA for Python](https://docs.oracle.com/en/database/oracle/simple-oracle-document-access/python/). Both Functions are exposed using API Gateway.

• _store-data_ → This Function creates a collection called _DataSyncCollection_ in AJD, _jsonDB_ if collection is not existing and then populate the collection with the data posted by the source application. Each call to this Function adds a new record in the _DataSyncCollection_.

•_process-data_ → This Function is used to do the processing of JSON payload as well as retrial of failed payloads in the _DataSyncCollection_ . 

When it is used for initial processing, it uses the SODA QBE filters and look for JSON documents which are not processed. When it is used for retrials , it uses SODA QBE filters and look for JSON documents which are of failed status.

[API Gateway](https://docs.oracle.com/en-us/iaas/Content/APIGateway/)

There is one API Gateway used, _SyncDataGateway_. There are 3 routes defined in API Gateway deployment,_SyncUsingJSONDB_. One is to map the Function _store-data_ to the route _/store_, 2nd is to map the _process-data_ Function to the route _/process_  and 3rd is to map the _process-data_ Function to the route _/process/retry_


[Vault](https://www.oracle.com/in/security/cloud-security/key-management/)

A vault called, _DataSyncVault_ is used to store the authorization header tokens sent by the Source Application as secrets.
The database schema password to connect to AJD, also is added in the same vault.


[HashiCorp Terraform](https://www.Terraform.io/)

[Oracle Terraform Provider](https://registry.Terraform.io/providers/hashicorp/oci/latest/docs)

[Python](https://www.python.org/)
  - [Oracle Cloud Infrastructure SDK for Python](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/pythonsdk.htm)
  - [SODA for Python](https://docs.oracle.com/en/database/oracle/simple-oracle-document-access/python/)
  

## Architecture

![Architecture]( /image/Architecture.png "Architecture Diagram")

## Process Flow

Step 1.	Source application/s posts data to the API Gateway deployment route with path ,_/store_ . This invokes the Function _store-data_.

The REST API call to API Gateway and sample json payload is given below. 
https://[hostname]/jsondb/store

```
{
        "vaultSecretName":"vaultsecret1",
		"targetRestApi": "https://g.../.../latest/orders",
		"targetRestApiOperation": "POST",
		"targetRestApiPayload": {
			"orderid": "20jan1",
			"PO": "19jan"
		},
		"targetRestApiHeaders": {
			 "Content-Type": "application/json"
			}
		
	

}
```


The payload  is self-contained i.e.  it contains the target application API in _targetRestApi_ node,  target application’s Rest API operation in _targetRestApiOperation_ key and a target application’s Rest API payload in _targetRestApiPayload_ node. Headers for target REST API call should be sent in _targetRestApiHeaders_ node.

In most cases the target application API will need a security token. Usually this token is passed in the authorization header of the POST call to API Gateway. This token needs to be securely stored for target application API processing later by _process-data_ Function. For this purpose,  the json payload contains a  key called _vaultSecretName_ which is an id that should be unique to messages that has the same auth token.  The unique id will be used as a secret name in the Vault and the secret content will be the auth token passed in the authorization header. When the auth token in the authorization header changes, a new ubique value should be passed in the _vaultSecretName_ for those messages.

Step 2.	_store-data_  inserts the JSON payload into _datasync_collection_. It adds 2 new keys to json payload. One is  called , _status_ with value as _not_processed.  The second one is _createdDate_ with value as current date& time. These keys will be used by _process-data_ Function to filter and sort the records.
It also reads the _vaultSecretName_ and creates a secret in Vault with content as the authorization header token and secret name as the value of the key _vaultSecretName_.

Step 3.	_process-data_  Function which is exposed in API Gateway using the route with path _/process_, can be invoked sequentially to process the records. The API endpoint will be https://[host-name]/jsondb/process. 
The payload for this API, will look like below sample.

```
{
	
	"no_of_records_to_process": 2

   
}
```

The sequential invocation of the REST api should be automated. This Function reads through the DB and looks for JSON documents that are of _status_ as _not_processed_, ordered by the _createdDate_. The number of records to process by a single call of the Function is defined in the _no_of_records_to_process_ value in the payload.

It then calls the target application's REST endpoint by reading the value of the key _targetRESTApi_ and  using the method in _targetRestApiOperation_. 
If the call is successful, the JSON document in the collection is updated with  _status_ key  value as _success_ and the _status_code_ as the REST response code of the target application API.

If the call is failed, the JSON document in the collection is updated with  _status_ key  value as _failed_ and the _status_code_ as the REST response code of the target application API. Function also adds a _failure_reason_ key with the reason for the target application call failure.

The response from the Function call will look like below. It gives the count of the total processed records, failed and successful records. It has a _has_next_ key that indicates whether there are further records in the database, with _status_ as _not_processed_. This helps in determining whether further call is required to the Function.

```{"total_processed_records":1,"success_count":0,"failure_count":1,"has_next:"false"}```

Step 5.	Lastly there is an option to retry the failed messages  using an API Gateway API, that exposes the _process-data_ Function, in a route _/process/retry_

The sample REST API call and  payload looks like this.

https://[host-name]/jsondb/process/retry 

```
{
	
	"no_of_records_to_process": 2,
	"retry_codes":"503,500",
    "retry_limit":3
   
}

```


In the retry payload, specify the _no_of_records_to_process_, which tells the number of records to process by a single call of the Function. _retry_codes_ is where you can specify the response codes that should be retried.
It also contains an option to set the number of times retry should happen using _retry_limit_.

This Function queries the database for JSON documents with _status_ as _failed_ and with _status_code_ matching the _retry_codes_. If the processing of record has already been tried to a number equal to _retry_limit_, then those records are skkiped. This api call, sends a response as below

`{"total_processed_records":1,"success_count":0,"failure_count":1,"skipped_count":0,"has_next:"false"}`

In case of retry, the response informs, the number of JSON documents skipped from processing since retrial count has reached the limit for those documents. This is indicated by the value in _skipped_count_ .


## Installation



### Pre-requisites

1. Make sure you've setup your [API signing key](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm), installed the [Fn CLI](https://github.com/fnproject/cli), completed the [CLI configuration](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/sdkconfig.htm#CLIConfiguration) steps and have setup the [OCI Registry](https://docs.cloud.oracle.com/iaas/Content/Registry/Concepts/registryoverview.htm) you want to use.

2. Ensure Terraform is installed.

3. You have the Target application's REST API, Auth token and Json Payload for loading data to it.

### Creating the cloud artefacts in OCI

1. Download the files from the respository and navigate to location where you downloaded the files. Navigate to _code_ folder.

2. Modify _provider.tf_ , with values spefic to your OCI environment.

3. Run following Terraform  commands to create all your resources in OCI. You will be asked the provide variable values. 

	- _terraform init_

	- _terraform plan_

	- _terraform apply_


4. This step creates all the resources in OCI , including the setup of a VCN, an API Gateway, Streams, Service Connectors, Notifications,  Object Storage Bucket,uploading the Oracle Cloud Functions and creating an OCI Vault.

5. Log In to OCI console and verify whether all OCI resources are created.

6. Add [IAM policies](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/commonpolicies.htm) related to usage of Functions, Streams, Service Connector, Object Storage and Notifications



### Running the sample

1. Make sure that a database user is created in the AJD and you are able to connect to the database user. 

2. Create a new secret in Vault _DataSync_Vault_ with name as _db_pwd_. Enter your databse user password as the secret content.

2. Get the Endpoint of the API Gateway deployment _SyncUsingJSONDB_.  Append the endpoint with the path /store. The API will look like this, https://[host-name]/jsondb/store 

3.  Make the REST call to the above  endpoint.  The curl command will look this,

		curl --location --request POST 'https://pfk2ep3pw3x3tcx4iemcx4gj4q.apigateway.us-ashburn-1.oci.customer-oci.com/jsondb/store' \
		--header 'Authorization: Basic YWRtaW46V2VsY29tZTEyMzQq' \
		--header 'Content-Type: application/json' \
		--data-raw '{
			
			"vaultSecretName":"mar1234",
				"targetRestApi": "https://g4kz1wyoy/latest/orders",
				"targetRestApiOperation": "POST",
				"targetRestApiPayload": {
					"orderid": "20jan1",
					"PO": "19jan"
			},
				"targetRestApiHeaders": {
					"Content-Type": "application/json"
					}
				
			

		}

Change the values based on your Target application's REST api. Pass the authorization header to connect to target application's REST end point.

This API call will insert a record in the collection called _datasync_collection_ in AJD. The JSON payload will be stored in the JSON_DOCUMENT column in the table, _DataSyncCollection_. Check the table to verify if the record is successfully inserted. You can use the Database Actions menu in AJD to inspect the databse contents. There are various options available once the Database Actions is launched, like SQL, JSON etc.

The inserted JSON document in the table , will have 2 additional keys called , _status_ with value as _not_processed_ and _createdDate_ with value as time of data insertion.


4. Next,  Run the process api,https://[host-name]/jsondb/process. The curl command will look this,

		curl --location --request POST 'https://pfk2ep3pw3x3tcx4iemcx4gj4q.apigateway.us-ashburn-1.oci.customer-oci.com/jsondb/process/retry' \ 
		--header 'Authorization: Basic YWRtaW46V2VsY29tZTEyMzQq' \
		--header 'Content-Type: application/json' \
		--data-raw '{
			
			"no_of_records_to_process": 2
			
		
		}'
		
Check the response, to see if the _total_processed_records_ is 1 and _success_count_ is 1. If _success_count_ is 1, check the Target APplication and verify if the REST api operation is successful.
If the _success_count_ is 0, and _failed_count_ is 1, Check the database and see the _failure_reason_ key in the JSON document.

5. To validate if the retry is working, you can pass incorrect values in the _store_ api payload and then invoke, the retry api. The retry api,  will look like this
https://[host-name]/stream/retry. 

The curl command will look like below.

		curl --location --request POST 'https://pfk2ep3pw3x3tcx4iemcx4gj4q.apigateway.us-ashburn-1.oci.customer-oci.com/jsondb/process/retry' \
		--header 'Authorization: Basic YWRtaW46V2VsY29tZTEyMzQq' \
		--header 'Content-Type: application/json'\
		--data-raw '{
			
			"no_of_records_to_process": 2,
			"retry_codes":"503,500",
			"retry_limit":3
		
		}'





Replace the retry_codes with _status_code_ of the failed records. You can also change _no_of_records_to_process_ to a higher or lower value, depending on the Function time out._retry_limit_ can also be changed to a different no. based on your requirement.


### Enhancing the sample
Please note that the sample given is only to demonstrate a pattern and mostly you will need to enhance it to fit into your needs.

While enhancing the sample do consider the following.

-  You can use Oracle Apex to build an adminstration tool to view the data and take corrective actions in case of data failure.


•	You will need a process to delete the Vault secrets once they are no longer needed. One option is to write a Function, that can do the clean-up task periodically.

•	retry and process call payload has the key _no_of_records_to_process_ to set the no of JSON documents to process in a single call. Do change this to a smaller number if processing of each document takes time and there is a possibility of Function to time out.

•	retry and process call response  _has_next_ key has a value either true or false. It indicates if there are further records available for processing.
 To process large number of messages together,invoke retry sequentially after checking if  _has_next_ key value of the previous call.

•	The sample function handles PUT, POST and DELETE operations. To add or remove operations, change the _process-data_ Function code. Also change the _targetRestApiOperation_ section of the payload.

•	The source application is responsible for sending unique value in the vaultsecretname for messages having same auth token.

•	It is assumed that the authentication token to invoke the target application’s REST api is passed in the “Authorization” Header. There is a possibility that authorization token stored in Vault expires while retrying the message. This scenario is not considered in the sample. 


## Troubleshooting

- If things dont work, here are some [troubleshooting tips for Oracle Cloud Functions](https://docs.cloud.oracle.com/en-us/iaas/Content/Functions/Tasks/functionstroubleshooting.htm) you can try.

- The Oracle Cloud Functions are configured to emit logging info using standard system logging, this can be useful when debugging the functions. 

-  Make sure you have defined all the required IAM policies.


## Security

Oracle takes security seriously and has a dedicated response team for [reporting security vulnerabilities](./SECURITY.md) and to answer any security and vulnerability related questions.

## Contributing

We welcome all contributions to this sample and have a [contribution guide](./CONTRIBUTING.md) for you to follow if you'd like to contribute.

## Help

If you need help with this sample, please log an issue within this repository and the code owners will help out where we can.

Copyright (c) 2022, Oracle and/or its affiliates. Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
