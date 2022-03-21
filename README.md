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


Oracle Autonomous JSON Database is a cloud document database service that makes it simple to develop JSON-centric applications. 
The AJD used in this sample is named as _jsonDB_.


[SODA](https://docs.oracle.com/en/database/oracle/simple-oracle-document-access/)

This sample uses SODA APIs to access Autonomous JSON databse. SODA abstractions hide the complexities of SQL and client programming using

1. Collection
2. Document


**Collection**

A SODA collection is analogous to an Oracle Database table or view.  A document collection contains documents. 
Collections are persisted in an Oracle Database schema . A database schema is referred to as a SODA database.

Even Though SODA is designed primarily for working with JSON documents, but a document can be of any Multipurpose Internet Mail Extensions (MIME) type.

In addition to its content, a document has other document components, including a unique identifier, called its key, a version, a media type (type of content), and the date and time that it was created and last modified. 

The key is typically assigned by SODA when a document is created, but client-assigned keys can also be used. The other components are generated and maintained by SODA. All components other than content and key are optional.

**Document**

A SODA document is analogous to, and is in fact backed by, a row of a database table or view. The row has one column for each document component: key, content, version, and so on.

SODA provides CRUD operations on documents. JSON documents can additionally be queried, using query-by-example (QBE) patterns, also known as filter specifications. A filter specification is itself a JSON object.

In this sample, a single collection is used _DataSyncCollection_. This collection contains the json payload posted by the source application.


[Functions](https://www.oracle.com/cloud-native/functions/)

Functions are under an Application, _DataSyncWithJSONDB_ . It has the following configuration variables. They are for defining the AJD connections, Vault OCIDs,  etc

_DBUSER_ is the database schema to connect to.
_DBSVC_ is the database service name.
In addition to these configuration contains OCIDs of various services.


![Application configuration variables]( /image/ApplicationConfiguration.png "Application configuration variables")

2 Functions are used in this pattern. They are python Functions and uses [SODA for Python](https://docs.oracle.com/en/database/oracle/simple-oracle-document-access/python/). Both Functions are exposed using API Gateway.

• _store-data_ → This Function creates a collection called _DataSyncCollection_ in AJD, _jsonDB_ if collection is not existing and then populate the collection with the data posted by the source application. Each call to this Function adds a new record in the _DataSyncCollection_.

•_process-data_ → This Function is used to do the initial processing of records as well as retrial of failed records in the _DataSyncCollection_ . 

When it is used for initial processing, it uses the SODA QBE filters and look for records which are not processed. When it is used for retrials , it uses SODA QBE filters and look for records which are of failed status.

[API Gateway](https://docs.oracle.com/en-us/iaas/Content/APIGateway/)

There is one API Gateway used, _SyncDataGateway_. There are 3 routes defined in API Gateway deployment,_SyncUsingJSONDB_. One is to map the Function _store-data_ to the route _/store_, 2nd is to map the _process-data_ Function to the route _/process_  and 3rd is to map the _process-data_ Function to the route _/process/retry_


[Vault](https://www.oracle.com/in/security/cloud-security/key-management/)

A vault called, _DataSyncVault_ is used to store the auth tokens as secrets.
The databse schema password to connect, also is present in the same vault.


[HashiCorp Terraform](https://www.Terraform.io/)

[Oracle Terraform Provider](https://registry.Terraform.io/providers/hashicorp/oci/latest/docs)

[Python](https://www.python.org/)
  - [Oracle Cloud Infrastructure SDK for Python](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/pythonsdk.htm)
  

## Architecture

![Architecture]( /image/Architecture.png "Architecture Diagram")

## Process Flow

Step 1.	Source application/s posts data to the REST API exposed by the API Gateway. The API gateway has an API deployment with route with path ,_/store_ that invokes the Function _store-data_.

The REST API call to API Gateway and sample json payload is given below. 
https://[hostname]/jsondb/store




```
{
       "createdDate":"2022-03-14 11:35:49.966290000",
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


The payload  is self-contained i.e.  it contains the target application API in _targetRestApi_ node,  target application’s Rest API operation in _targetRestApiOperation_ node and a target application’s Rest API payload in _targetRestApiPayload_ node. Headers for target REST API call should be sent as key , value pair in _targetRestApiHeaders_ node.

In most cases the target application API will need a security token. Usually this token is passed in the authorization header of the POST call to API Gateway. This token needs to be securely stored for target application API processing later by Functions. For this purpose,  the json payload contains a  node called _vaultSecretName_ which is an id that should be unique to messages that has the same auth token passed in authorization header.  The unique id will be used as a secret name in the Vault and the secret content will be the auth token passed in the authorization header. When the auth token in the authorization header changes, a new value should be passed in the _vaultSecretName_ for those messages.

_createdDate_ is used internally by the Functions to sort the records based on the date. Pass the date and time in this field.


Step 2.	_store-data_  inserts the JSON payload into _datasync_collection_. It adds a new node to json payload called , _status_ with value as _not_processed. This node will be used by _process-data_ Function to filter the records.
It also reads the _vaultSecretName_ and creates a secret in Vault with content as the authorization header token and secret name as the value of the node _vaultSecretName_.

Step 3.	_process-data_  Function which is exposed in API Gateway using the route with path _/process_, can be invoked sequentially to process the records. The API endpoint will be https://[host-name]/jsondb/process. 
The sequential invocation of the REST api should be automated. This Function reads through the DB and looks for records that are of _status_ as _not_processed_, ordered by the _createdDate_. It then calls the target applications REST endpoint by reading the value of the node _targetRESTApi_
using the method in _targetRestApiOperation_. 
The number 
```
{
	
	"no_of_records_to_process": 2

   
}
```


Step 5.	Lastly there is an option to retry the failed messages  using an API Gateway API, that exposes the _process-data_ Function, in a route _/process/retry_

The sample REST API call and  payload will look like this.

https://[host-name]/jsondb/process/retry

```
{
	
	"no_of_records_to_process": 2,
	"retry_codes":"503,500",
    "no_of_times_to_retry":3
   
}

```


In the retry payload, specify the stream OCID to retry using  _streamOCIDToRetry_ and the offset from where the retry should happen. 
_noOfMessagesToProcess_ is the no of Stream messages to process in a single Function call.

_readAfterOffset_ is the offset location from where the messages are to be read. Set this to -1 to start reading from the oldest message in the Stream. 

The payload also contains an _errormapping_ section to specify the streams to which errored messages should be directed to. _streamOCIDToRetry_ option in the retry payload gives flexibility of retrying messages in any stream.

_errormapping_ option in the payload gives the flexibility of changing error stream mapping based on the stream which is retried and the expected error scenario.

This API's response body will have information on the last offset which was successfully processed, no. of successfully  processed messages and no. of failed messages. 

`{"lastReadOffset":405 ,"processedmessages":0,"failedMessages":1,"endOfStream": true}`

It also informs whether end of Stream has reached, so that further call for retrial can be stopped if there is no more message to process.



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

1. To run the sample, get the API Gateway URL corresponding to _sync_ route. It will look like following, https://[host-name]/jsondb/store


A sample json payload is given below. You can have POST, PUT and DELETE operatons. Change the _targetRESTApi_ and _targetRESTApiOperation_ values based on your target application.
Any REST API headers should be passed as key, value pairs in _targetRestApiHeaders_.
```
{
	"streamKey": "key1",
	"streamMessage": {
	   "vaultSecretName":"789",  
	    
		"targetRestApi": "https://g....../latest/orders",
		"targetRestApiOperation": "POST",
		"targetRestApiPayload": {
			"orderid": "18jan",
			"PO": "18jan"
		},
		"targetRestApiHeaders": [{
				"key": "Content-Type",
				"value": "application/json"
			}
		]
	}

}
```

This API call will insert a record in the collection called _datasync_collection_ in AJD. The record will be stored in the JSON_DOCUMENT column in the table.

1. Run the process api,https://[host-name]/jsondb/process . The response payload will contain,information on how many records were processed and the success_count/Failure_count.
``` {"total_processed_records":5,"success_count":5,"failure_count":0,"has_next:"true"}```
   
3. Check the target application to see the operations invoked were processed correctly. You can also login to AJD and check the status field of the processed records.

2. To check for retry and failures, you can pass incorrect values in the payload and see whether the Error Streams got populated correctly. In case of errors, you will also receive notifications in the mail id you entered in Notifications Service. You can also see the errored messages in the Object Storage Bucket.

3. To test a retry in case of failure, call the API Gateway REST API, corresponding to _retry_ route. It will look like this
https://[host-name]/stream/retry

Sample payload is given below.

Replace the _streamOCIDToRetry_ with the OCID of the error stream to be retried.

_noOfMessagesToProcess_ is the no of Stream messages to process in a single Function call.

_readAfterOffset_ is the offset location from where the messages are to be read. Set this to -1 to start reading from the oldest message in the Stream. 

 _RetryFunction_ will process the messages and return the last successfully read offset. So if this API needs multiple invocation, read the response body of the API and make subsequent call by passing the last offset as the _readAfterOffset_ value in the payload.

Also replace, _stream_ value in the _errormapping_ section with the error streams in your OCI environment. 
```
{
	"streamOCIDToRetry": "ocid1.stream.o...rrr",
	"noOfMessagesToProcess": 5,
	"readAfterOffset": -1,
	"readPartition": "0",
	"errormapping": [{
			"responsecode": "404",
			"stream": "ocid1.stream.oc1.iad...r"
		},
		{
			"responsecode": "503",
			"stream": "ocid1.stream.oc1.iad.am.."
		}, {
			"responsecode": "unexpectedError",
			"stream": "ocid1.stream.oc1.iad.a...q"
		}
		
	]


}
```
### Enhancing the sample
Please note that the sample given is only to demonstrate a pattern and mostly you will need to enhance it to fit into your needs.

While enhancing the sample do consider the following.


•	You will need a process to delete the Vault secrets once they are no longer needed. One option is to write a Function, that can do the clean-up task periodically.

•	retry and process call payload has the node _no_of_records_to_process_ to set the no of messages to process in a single call. Do change this to a smaller number if processing of each message takes time and there is a possibility of Function to time out.

•	retry and process call response  _has_next_ node which is either true or false. It indicates if there are further records available for processing.
 To process large number of messages together,invoke retry sequentially after checking if  _has_next_ node value of the previous call.

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
