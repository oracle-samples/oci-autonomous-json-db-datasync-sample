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


[Autonomous JSON DB](https://www.oracle.com/cloud-native/streaming/)


Streaming is a good fit for any use case in which data is produced and processed continually and sequentially in a publish-subscribe messaging model. Additionally, it can connect to Service Connector Hub which means that you can designate a stream as a data source, use Oracle Cloud Infrastructure Functions to process the stream's messages. It is also is  a fully managed and scalable OCI service. Customers need to pay only for what they use, making the service attractive for workloads with large spikes in usage.

There are 2 types of streams used.

•	A stream, _DataSyncStream_ for storing the posted data from the source application/s.

•	A stream or streams for storing errored data. Posting of data to target application/s can error out due to multiple reasons, like server unavailability, data inconsistency, error on the server side while processing and so forth. Some of these errors are recoverable, say an error occurred due to server unavailability is recoverable when server is available. Some of them would be unrecoverable, i.e. the processing of data will not be successful even after several retrials. It is important to categorize and re-process errored messages based on the error type to avoid data loss. In the sample code developed for this pattern, retrial is based on the REST API response code. Please note that, the error type and retrial decision is based on the business use case and using REST API response code may not be suitable for all business cases.
The data will be moved from _DataSyncStream_  to Error streams based on the error type and classification. 


[Functions](https://www.oracle.com/cloud-native/functions/)

Functions are under an Application, _DataSyncWithJSONDB_ . It has the following configuration variables. They are for defining the AJD connections, Vault OCIDs, retry_codes etc


![Application configuration variables]( /image/ApplicationConfiguration.png "Application configuration variables")

2 Functions are used in this pattern. 
• _store-data_ → This Function is used to populate the _DataSyncWithJSONDB_ . It is invoked when the Source Application/s post data to the REST API exposed using API Gateway. 
•_process-data_ → This Function reads the records in  _DataSyncWithJSONDB_ and looks for records which in _not_processed_ status. It reads the json data and calls the target application’s API. If there is a failure in target application API call, the JSON data in the record is updated with 
   ``` "status": "failed" ``` and   ``` "status_code": ``` as the REST api response code. If the Target application API call is a success, the JSON data in the record is updated with 
   ``` "status": "success" ``` and   ``` "status_code": ``` as the REST api response code. 

This Function code is also used for retrials of failed records. The status_code for which retrials has to happen is defined in the application configuration variables. When this Function is executed for retrial, then it looks for records which in _failed_ status and with _status_code_ defined in the configuration. 
  



[API Gateway](https://docs.oracle.com/en-us/iaas/Content/APIGateway/)

There is one API Gateway used, _SyncDataGateway_. There are 3 routes defined in API Gateway deployment,_SyncUsingJSONDB_. One is to map the Function _store-data_ to route _/store_, 2nd is to map the _process-data_ Function to route _/process_  and 3rd is to map the _process-data_ Function to route _/process/retry_





[Vault](https://www.oracle.com/in/security/cloud-security/key-management/)

A vault called, _DataSyncVault_ is used to store the auth tokens as secrets.


[HashiCorp Terraform](https://www.Terraform.io/)

[Oracle Terraform Provider](https://registry.Terraform.io/providers/hashicorp/oci/latest/docs)

[Java](https://www.oracle.com/java/)
  - [Oracle Cloud Infrastructure SDK for Java](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/javasdk.htm)
  

## Architecture

![Architecture]( /image/Architecture.png "Architecture Diagram")

## Process Flow

Step 1.	Source application/s posts data to the REST API exposed by the API Gateway. The API gateway  has an API deployment that invokes the Function _PopulateDataStreamFunction_.

The REST API call to API Gateway and sample json payload is given below. 
https://[hostname]/stream/sync


```
{
	"streamKey": "key1",
	"streamMessage": {
	   "vaultSecretName":"789",  
	    
		"targetRestApi": "https://g4kz1wyoyzrtvap-json......./....../latest/orders",
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



The json payload contains  _streamKey_ and _streamMessage_ nodes. _streamKey_ is the key to be sent to the _DataSyncStream_ and _streamMessage_ is the value to be sent to the _DataSyncStream_. _streamKey_  can be empty if a key is not required while populating streams.

The _streamMessage_ section  is self-contained i.e.  it contains the target application API in _targetRestApi_ node,  target application’s Rest API operation in _targetRestApiOperation_ node and a target application’s Rest API payload in _targetRestApiPayload_ node. Headers for target REST API call should be sent as key , value pair in _targetRestApiHeaders_ node.

In most cases the target application API will need a security token. Usually this token is passed in the authorization header of the POST call to API Gateway. This token needs to be securely stored for target application API processing later by Functions. For this purpose,  the json payload contains a  node called _vaultSecretName_ which is an id that should be unique to messages that has the same auth token passed in authorization header.  The unique id will be used as a secret name in the Vault and the secret content will be the auth token passed in the authorization header. When the auth token in the authorization header changes, a new value should be passed in the _vaultSecretName_ for those messages.


Step 2.	_PopulateDataStreamFunction_  parses the json payload and creates a new stream message with Key as _streamKey_ and value as _streamMessage_ and pushes it to _DataSyncStream_. It also reads the _vaultSecretName_ and creates a secret in Vault with content as the authorization header token and name as _vaultSecretName_.

Step 3.	_DataSyncStream_  is connected to the Function, _ReadDataStreamFunction_ through a Service Connector. Service Connector invokes this Function when _DataSyncStream_ is populated with new messages.

Step 4. _ReadDataStreamFunction_ processes the messages in DataSyncStream by reading the _targetRestApiPayload_ section and then invokes the target application API. If an error occurs, say if the server is unavailable Function pushes the message to error streams defined in the Function Application configuration variables.


Step 5.	Lastly there is an option to retry the messages in Error streams using an API Gateway API, that exposes the _RetryFunction_.

The sample REST API call and  payload will look like this.

https://[host-name]/stream/retry

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

1. To run the sample, get the API Gateway URL corresponding to _sync_ route. It will look like following, https://[host-name]/stream/sync


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

This API call will push the _streamMessage_ part of the payload to _DataSyncStream_ . The Service Connector which connects _DataSyncStream_  to Functions will get invoked and the associated Task Function ,_ProcessDataStreamFunction_ will read the stream message and process the messages.

2. Check the target application to see the operations invoked were processed correctly.

3. To check for retry and failures, you can pass incorrect values in the payload and see whether the Error Streams got populated correctly. In case of errors, you will also receive notifications in the mail id you entered in Notifications Service. You can also see the errored messages in the Object Storage Bucket.

4. To test a retry in case of failure, call the API Gateway REST API, corresponding to _retry_ route. It will look like this
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

•	The function application configuration has a few error stream OCIDs defined. Add new error streams or modify the existing ones based on your requirement. Note that, the _ReadDataStreamFunction_ code should be modified if changes are made in the configuration keys.

•	Change the _errormapping_ section of RetryFunction payload, if needed. The sample makes use of the response code for mapping streams. Change this, if a different type of mapping is required. _RetryFunction_ code also would need change if there is a change in the payload.

•	You will need a process to delete the Vault secrets once they are no longer needed. One option is to write a Function, that can do the clean-up task periodically.

•	_RetryFunction_ payload has the node _noOfMessagesToProcess_ to set the no of messages to process in a single call. Do change this to a smaller number if processing of each message takes time and there is a possibility of Function to time out.

•	Consuming messages from a stream requires you to: create a cursor, then use the cursor to read messages. A cursor is a pointer to a location in a stream. One of the option is to use a  specific offset to start the reading of message. This is called an AT_OFFSET cursor. 
RetryFunction in the sample uses the AT_OFFSET cursor for consuming message. It accepts _readAfterOffset_ as the starting offset to read message. It returns the last successfully read offset. To process large number of messages together, store returned offset value in a location and pass it as  value of _readAfterOffset_ in json payload and  invoke _RetryFunction_ sequentially.

•	The sample function handles PUT, POST and DELETE operations. To add or remove operations, change the _ReadDataStreamFunction_ and _RetryFunction_ code. Also change the _targetRestApiOperation_ section of the payload.

•	The source application is responsible for sending unique value in the vaultsecretname for messages having same auth token.

•	It is assumed that the authentication token to invoke the target application’s REST api is passed in the “Authorization” Header. There is a possibility that authorization token stored in Vault expires while retrying the message. This scenario is not considered in the sample. 

•	It is also possible to move the common methods in Functions to helper classes and reusing them.


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
