[comment]: # "Auto-generated SOAR connector documentation"
# ThreatQ

Publisher: ThreatQuotient  
Connector Version: 1\.0\.2  
Product Vendor: ThreatQuotient  
Product Name: ThreatQ  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 1\.2\.236  

Integrates a variety of ThreatQ services into Phantom\.





### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ThreatQ asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tq\_server** |  required  | string | Server IP/Hostname
**clientid** |  required  | string | Client ID
**username** |  required  | string | Username
**password** |  required  | password | Password
**trust\_ssl** |  required  | boolean | Trust SSL Certificate?

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\.  
[run query](#action-run-query) - Query ThreatQ and grab attributes  
[create ioc](#action-create-ioc) - Create IOC in ThreatQ  
[get related iocs](#action-get-related-iocs) - Query ThreatQ for related IOCs  
[link ioc](#action-link-ioc) - Link IOCs together  
[create event](#action-create-event) - Create event based on current container  
[upload file](#action-upload-file) - Upload file from vault in current container  
[domain reputation](#action-domain-reputation) - Get attributes, related indicators, and related adversaries  
[ip reputation](#action-ip-reputation) - Get attributes, related indicators, and related adversaries  
[email reputation](#action-email-reputation) - Get attributes, related indicators, and related adversaries  
[url reputation](#action-url-reputation) - Get attributes, related indicators, and related adversaries  
[file reputation](#action-file-reputation) - Get attributes, related indicators, and related adversaries  
[update status](#action-update-status) - Change Indicator Status in ThreatQ  
[create adversary](#action-create-adversary) - Create Adversary in ThreatQ  

## action: 'test connectivity'
Validate the asset configuration for connectivity\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'run query'
Query ThreatQ and grab attributes

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query | string |  `domain`  `ip`  `email`  `url`  `hash`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string |   

## action: 'create ioc'
Create IOC in ThreatQ

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator** |  required  | indicator | string |  `domain`  `ip`  `email`  `url`  `hash`  `string` 
**indicator\_type** |  required  | indicator type | string | 
**indicator\_status** |  required  | indicator status | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.indicator | string | 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.indicator\_status | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.value | string |  `domain`  `ip`  `email`  `url`  `hash` 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.url | string | 
action\_result\.data\.\*\.existing | boolean |   

## action: 'get related iocs'
Query ThreatQ for related IOCs

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Indicator to query | string |  `domain`  `ip`  `email`  `url`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.value | string |  `domain`  `ip`  `email`  `url`  `hash` 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.url | string |   

## action: 'link ioc'
Link IOCs together

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_1** |  required  | Indicator | string |  `domain`  `ip`  `email`  `url`  `hash` 
**indicator\_2** |  required  | Indicator to Link To | string |  `domain`  `ip`  `email`  `url`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.indicator\_1 | string | 
action\_result\.parameter\.indicator\_2 | string |   

## action: 'create event'
Create event based on current container

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.data\.\*\.eid | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.url | string |   

## action: 'upload file'
Upload file from vault in current container

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Valult ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.vault\_id | string | 
action\_result\.data\.\*\.fid | string | 
action\_result\.data\.\*\.file\_name | string | 
action\_result\.data\.\*\.url | string |   

## action: 'domain reputation'
Get attributes, related indicators, and related adversaries

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query | string |  `domain`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.status\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.type\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.source\_name | string |   

## action: 'ip reputation'
Get attributes, related indicators, and related adversaries

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query | string |  `ip`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.status\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.type\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.source\_name | string |   

## action: 'email reputation'
Get attributes, related indicators, and related adversaries

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query | string |  `email`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.status\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.type\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.source\_name | string |   

## action: 'url reputation'
Get attributes, related indicators, and related adversaries

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query | string |  `url`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.status\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.type\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.source\_name | string |   

## action: 'file reputation'
Get attributes, related indicators, and related adversaries

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query | string |  `hash`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.data\.\*\.attributes\.\*\.name | string | 
action\_result\.data\.\*\.attributes\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.indicators\.\*\.status\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.type\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.indicators\.\*\.adversaries\.\*\.source\_name | string |   

## action: 'update status'
Change Indicator Status in ThreatQ

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator** |  required  | Indicator | string |  `domain`  `ip`  `email`  `url`  `hash`  `string` 
**new\_status** |  required  | New Status | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.indicator | string | 
action\_result\.parameter\.new\_status | string |   

## action: 'create adversary'
Create Adversary in ThreatQ

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**adversary\_name** |  required  | Adversary Name | string |  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.status | string | 
action\_result\.parameter\.adversary\_name | string | 
action\_result\.data\.\*\.aid | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.url | string | 