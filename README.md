[comment]: # "Auto-generated SOAR connector documentation"
# Microsoft Exchange On\-Premise EWS

Publisher: Splunk  
Connector Version: 3\.7\.6  
Product Vendor: Microsoft  
Product Name: Exchange  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app performs email ingestion, investigative and containment actions on an on\-premise Exchange installation

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Use the Microsoft Exchange On-Premise EWS app to access a user's mailbox via EWS XML SOAP calls on
an on-premise Exchange server. This can be done through impersonation, or high-level permissions. To
use Splunk Phantom to organize and gain insights from email data, you need to install and connect
Splunk Phantom to the Microsoft Exchange On-Premise EWS app.

## Impersonation and privileges

When using impersonation, the app uses the current user to impersonate the target user to perform
commands in the mailboxes the target user has access to. This can be configured in the user
interface. When using high level permissions, many organizations configure an Exchange administrator
account that has access to certain mailboxes. To give access to a user's mailbox to another user,
use the **Add-MailboxPermission** PowerShell cmdlet on the Exchange Server.

## Configuration

-   EWS URL: The URL configured by the person that set up the Exchange server.
-   EWS Version: Ensure the version in the dropdown corresponds to the version of Exchange you have
    installed. 
-   Username and Password: Use the username and password that have the correct privileges to access
    other mailboxes. 
-   (Optional) User Email Mailbox: The mailbox you will ingest data from if you use polling and to
    test connectivity. 
-   (Optional) Script with functions to preprocess containers and artifacts: The user can add a
    script file in the configuration parameter. The script must contain a function with the name
    **preprocess_container** (to pre-process the containers and the artifacts) else it will throw an
    error. The script should not contain **run_automation** (or any other logic to trigger active
    playbooks), as the app automatically handles the triggering. The code is implemented such that
    the container is first processed according to the script and then saved. The artifacts are then
    added to the container, after which the artifacts are processed and saved. Hence, when adding
    the script to process the artifacts, keep a check of if the artifacts are present in the
    container, then and then only modify it. 
-   On poll information: Configure your desired on poll settings. For example, how to ingest, the
    number of emails to poll, what type of information you want to extract, and once extracted, your
    desired level of container severity. For more information on using on poll data ingestion, see
    Use on poll data ingestion. 

## POLL NOW

POLL NOW should be used to get a sense of the containers and artifacts that are created by the app.
The POLL NOW window allows the user to set the "Maximum containers" that should be ingested at this
instance. Since a single container is created for each email, this value equates to the maximum
emails that are ingested by the app. The app will either get the oldest email first or the latest,
depending upon the configuration parameter *How to ingest* . The date used to determine the oldest
or latest is what EWS calls **item:LastModifiedTime** and **item:DateTimeCreated** , which is
dependent on the parameter *Sort mails by* . If an email that arrived a week ago, is moved from one
folder to the folder being ingested, its LastModifiedTime will be set to the time that it was moved.
But, its DateTimeCreated will be the same.  
  
**Note** : "Mailbox folder to be polled" parameter is case-sensitive.

## Scheduled Polling

This mode is used to schedule a polling action on the asset at regular intervals, which is
configured via the INGEST SETTINGS tab of the asset. It makes use of the following asset
configuration parameters (among others):

-   Maximum emails to poll the first time

      
    The app detects the first time it is polling an asset and will ingest this number of emails (at
    the most).

-   Maximum emails to poll

      
    For all scheduled polls after the first, the app will ingest this number of emails.

-   How to ingest

      
    Should the app be ingesting the latest emails or the oldest.

In the case of Scheduled Polling, on every poll, the app remembers the last email that it has
ingested and will pick up from the next one in the next scheduled poll.

### How to ingest

The app allows the user to configure how it should ingest emails on every scheduled poll either in
the *oldest first* or the *latest first* order. Depending upon the scheduled interval and how busy
the folder is, one of the following could potentially happen

-   oldest first

      
    If the app is configured to poll too slowly and the folder is so busy that on every poll the
    maximum ingested emails is less than the number of new emails, the app will never catch up.

-   latest first

      
    If the app is configured to poll too slowly and the folder is so busy that on every poll the
    maximum ingested emails is less than the number of new emails, the app will drop the older
    emails since it is ingesting the latest emails that came into the mailbox.

For best results, keep the poll interval and *Maximum emails to poll* values close to the number of
emails you would get within a time interval. This way, every poll will end up ingesting all the new
emails.

### Sort mails by

This parameter defines on which email attribute, the order *latest first* / *oldest first* should be
applied. The user can configure it to any of the below values.

-   updated time

      
    The application will fetch and ingest emails with the latest updated time field of the email
    attribute.

-   created time

      
    The application will fetch and ingest emails with the created time field of the email attribute.
    Be careful while using this option, as the application fetches the emails by the created time,
    any update made on the email after ingestion, will not be reflected in the phantom container.

  

In case the asset is configured to poll **oldest first** , it becomes important that the *Maximum
number of emails to poll* configured should be greater than the maximum number of emails generated
**per second** . If the app detects it got the maximum configured emails and all occurred in the
same second, it will start polling from the next second in the next polling cycle.

### Run automation on duplicate event

Set this parameter to run the automation, when there is a modification in the email which is already
ingested. If you don't want to trigger the automation for such small changes (in case of
re-ingestion), this parameter can be set to FALSE.

## Artifacts created

The app will create the following type of artifacts:

-   Email Artifact

      
    The email addresses that are found in the ingested email will be added as a separate artifact.
    Any attached email will also be scanned and the address present in the attached email will be
    added as a separate artifact. The emails are added as custom strings in the CEF structure in the
    following manner.  

    | **Artifact Field** | **Value Details**                                                                 |
    |--------------------|-----------------------------------------------------------------------------------|
    | fromEmail          | The email address of the sender                                                   |
    | toEmail            | The email address of the receiver of the email                                    |
    | emailHeaders       | A dictionary containing each email header as a key and its value as the key-value |

      
    [![](img/email_artifact.png)](img/email_artifact.png)

-   IP Artifact - cef.sourceAddress

      

    -   If **extract_ips** is enabled, any IPv4 or IPv6 found in the email body will be added, with
        one CEF per IP.
    -   Any IP addresses found in the email are added to the CEF structure of an artifact.
    -   The CEF for an IP is cef.sourceAddress.

-   Hash Artifact - cef.fileHash

      

    -   If **extract_hashes** is enabled, any hash found in the email body will be added, with one
        CEF per hash.
    -   Any Hashes found in the email are added to the CEF structure of an artifact.
    -   The CEF for a hash is cef.fileHash.

-   URL Artifact - cef.requestURL

      

    -   If **extract_urls** is enabled, any URL found in the email body will be added, with one CEF
        per url.
    -   Any URLs or hyperlinks found are added to the CEF structure of an artifact.
    -   The CEF for a URL is cef.requestURL.

-   Domain Artifact - cef.destinationDnsDomain

      

    -   If **extract_domains** is enabled, any domain found in the email body will be added, with
        one CEF per domain.
    -   Domains that are part of a URL, a hyperlink or an email address are added to the CEF
        structure of an artifact.
    -   The CEF for a Domain is cef.destinationDnsDomain.

-   Vault Artifact

    -   If the email contains any attachments, these are extracted (if **extract_attachments** is
        enabled) and added to the vault of the Container.
    -   At the same time, the vault ID and file name of this item is represented by a Vault
        Artifact.
    -   The same file can be added to the vault multiple times. In this scenario, the file name of
        the item added the second time onwards will be slightly different, but the vault ID will
        still be the same. However, there will be multiple artifacts created.
    -   Do note that the system does *not* duplicate the file bytes, only the metadata in the
        database.
        | **Artifact Field** | **Value Details**                                                                |
        |--------------------|----------------------------------------------------------------------------------|
        | Source ID          | Email ID set on the server                                                       |
        | cef.vaultId        | Vault ID of the attachment                                                       |
        | cef.fileHashMd5    | MD5 hash of the attachment                                                       |
        | cef.fileHashSha1   | SHA1 hash of the attachment                                                      |
        | cef.fileHashSha256 | SHA256 hash of the attachment                                                    |
        | cef.fileName       | File name of the attachment                                                      |
        | cef.headers        | A dictionary containing each file header as a key and its value as the key-value |
    -   You will notice additional CEF fields **cs6** (value is the Vault ID) and **cs6Label** .
        These are added for backward compatibility only and will be deprecated in future releases.
        Please don't use these keys in playbooks.

      
    [![](img/vault_artifact.png)](img/vault_artifact.png)

## Copy Email

To use the copy email command, follow these steps:

1.  Navigate to the Investigation page. 
2.  Click **Action** .
3.  In the search bar, search for the copy email command.
4.  Click **copy email** . 
5.  Click **exchange,** or whatever asset name you created, as the asset you want to run the **copy
    email** command on. 
6.  Enter the ID. Each email in Exchange has a unique ID. You can get this email ID from an email
    artifact that was previously ingested, or by running a run query action. 
7.  Enter the email address of the user you want to copy the email from and the folder you want to
    copy the email to.
8.   From the message ID, click the drop down arrow and click **Run Action** .
9.  Enter the email and the folder you want to move it to. 
10.  Click **Launch** . 

### Preprocessing Containers

It is possible to upload your own script which has functions to handle preprocessing of containers.
The artifacts which are going to be added with the container can be accessed through this container
as well. This function should accept a container and return the updated container. Also note that
the name of this function must be **preprocess_container** .

``` shell
import urlparse


def get_host_from_url(url):
    return urlparse.urlparse(url).hostname


def preprocess_container(container):

    # Match urls like https://secure.contoso.com/link/https://www.google.com
    # We want to strip 'https://secure.contoso.com/link/', and instead create
    #  a URL artifact for 'https://www.google.com'
    url_prepend = 'https://secure.contoso.com/link/'
    domain_prepend = 'secure.contoso.com'

    new_artifacts = []

    for artifact in container.get('artifacts', []):
        cef = artifact.get('cef')
        url = cef.get('requestURL')
        if url and url.lower().startswith(url_prepend):
            url = url.replace(url_prepend, '')
            artifact['cef']['requestURL'] = url
            # Create a new domain artifact for this URL
            new_artifacts.append({
                'name': 'Domain Artifact',
                'cef': {
                    'destinationDnsDomain': get_host_from_url(url)
                }
            })

        domain = cef.get('destinationDnsDomain')
        if domain and domain.lower() == domain_prepend:
            # These are the wrong domains, ignore them
            continue

        new_artifacts.append(artifact)

    if new_artifacts:
        new_artifacts[-1]['run_automation'] = True

    container['artifacts'] = new_artifacts
    return container
```

In this example, many of the URLs have 'https://secure.contoso.com/link' appended to the start of
them. These URL artifacts will be tough to use in a playbook without additional processing. On top
of that, all of the associated domain artifacts will be incorrect as well, since they will all point
to 'secure.contoso.com'.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Microsoft Exchange On-Premise EWS
Server. Below are the default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Exchange asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | EWS URL
**ph\_0** |  optional  | ph | 
**version** |  optional  | string | EWS Version
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**poll\_user** |  optional  | string | User Email Mailbox \(Test Connectivity and Poll\)
**use\_impersonation** |  optional  | boolean | Use Impersonation
**poll\_folder** |  required  | string | Mailbox folder to be polled
**is\_public\_folder** |  optional  | boolean | Mailbox folder is a public folder
**first\_run\_max\_emails** |  required  | numeric | Maximum emails to poll first time
**max\_containers** |  required  | numeric | Maximum emails for scheduled polling
**ingest\_manner** |  required  | string | How to ingest
**container\_severity** |  optional  | string | Container Severity
**ingest\_time** |  optional  | string | Sort mails by
**extract\_attachments** |  optional  | boolean | Extract Attachments
**extract\_urls** |  optional  | boolean | Extract URLs
**extract\_ips** |  optional  | boolean | Extract IPs
**extract\_domains** |  optional  | boolean | Extract Domain Names
**extract\_hashes** |  optional  | boolean | Extract Hashes
**extract\_email\_addresses** |  optional  | boolean | Extract Email Addresses
**add\_body\_to\_header\_artifacts** |  optional  | boolean | Add email body to the Email Artifact
**preprocess\_script** |  optional  | file | Script with functions to preprocess containers and artifacts
**unify\_cef\_fields** |  optional  | boolean | Unify CC/BCC CEF fields \(to uppercase\)
**automation\_on\_duplicate** |  optional  | boolean | Run automation on duplicate event

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[run query](#action-run-query) - Search emails  
[delete email](#action-delete-email) - Delete emails  
[copy email](#action-copy-email) - Copy an email to a folder  
[move email](#action-move-email) - Move an email to a folder  
[get email](#action-get-email) - Get an email from the server  
[list addresses](#action-list-addresses) - Get the email addresses that make up a Distribution List  
[lookup email](#action-lookup-email) - Resolve an Alias name or email address, into mailboxes  
[update email](#action-update-email) - Update an email on the server  
[on poll](#action-on-poll) - Ingest emails from the server into Phantom  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'run query'
Search emails

Type: **investigate**  
Read only: **True**

The <b>run query</b> action provides more than one method to search a user's mailbox\:<br><ul><li>Simple Search<br>Use the <b>subject</b> and <b>body</b> parameters to search for substring matches\. The <b>sender</b> parameter can be used to search for emails from a specific address\. However it has been noticed that a match with the <b>sender</b> email address fails for emails that have been never sent or received, but instead have been created manually as a draft and copied to the searched mailbox\. In such cases an AQS is a better option\. If more than one parameter is specified, the search is an <b>And</b> of the given values including the <b>internet\_message\_id</b>\.<br> <b>Simple Search</b> implements search filters\. More details regarding search filters can be found on this <a href="https\://msdn\.microsoft\.com/en\-us/library/office/dn579422\(v=exchg\.150\)\.aspx">MSDN Link</a>\.<br></li><li>Query Search<br>For a more fine\-grained email search, the use of the <b>query</b> parameter is recommended\. If this parameter is specified, the <b>subject</b>, <b>sender</b>, <b>internet\_message\_id</b> and <b>body</b> parameters are ignored\.<br>This parameter supports AQS queries to search in a Mailbox\. More details regarding AQS keywords supported by Exchange can be found on this <a href="https\://msdn\.microsoft\.com/en\-us/library/office/dn579420\(v=exchg\.150\)\.aspx">MSDN Link\.</a><br>Searching with AQS strings does have one notable restriction, however\. The AQS search string will only match substrings from the start of a word\. If a substring needs to be found in the middle of a word, use a <b>Simple Search</b>\.<br>Some examples\:<br><ul><li>All emails from user1\@contoso\.com or user2\@contoso\.com<br>from\:user1\@contoso\.com OR from\:user2\@contoso\.com</li><li>All emails containing the string <i>free vacations</i><br>body\: free vacations</li><li>This will match an email with subject containing the word <i>Details</i> but not <i>Cadet</i><br>subject\:det</li></li></ul></ul>If the <b>folder</b> parameter is not specified, each email based folder such as Inbox, Sent etc\. will be searched, including the children \(nested\) folders\.<br>The action supports searching a folder that is nested within another\.<br>To search in such a folder, specify the complete path using the <b>'/'</b> \(forward slash\) as the separator\.<br>For e\.g\. to search in a folder named <i>phishing</i> which is nested within \(a child of\) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>\.<br>NOTE\: In some cases search results may return more emails than are visible in an email client\. This is due to emails that have been just deleted, but not yet completely cleaned by the server\.<br><br>The action supports limiting the number of emails returned using the <b>range</b> parameter\. The input should be of the form <i>min\_offset</i>\-<i>max\_offset</i>\. The results are always sorted in <i>descending</i> order to place the latest emails at the top\. For example to get the latest 10 emails that matched the filter, specify the range as 0\-9\. If multiple folders are searched for, then the range will be applied for each folder\.<br>So if the folder being searched for example <i>Inbox</i> has a child \(nested\) folder called <i>phishing</i> and the range specified is 2\-10, then the action will return 9 max emails for each folder\. If the range parameter is not specified by default the action will use <b>0\-10</b>\.<br><br>NOTE\: The <b>email</b> parameter is required\.<br><br>Many actions such as <b>delete email</b> and <b>copy email</b> require the <b>exchange email ID</b> as input\. Many times this value is not easily available, since not many email clients display it\. However every email header has a value called <b>Message\-ID</b> assigned to it\. It's usually something like &lt;tS10Ncty2SyeJsjdNMsxV\+dguQ\+jd7RwiFgmZsLN\@contoso\.com&gt;\. Use this as the value \(including the &lt; and &gt; chars if present\) of <b>internet\_message\_id</b> parameter and execute the action\. The results will contain the <b>exchange email ID</b> of an email, which can be used as input for other actions\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | User's Email \(Mailbox to search in\) | string |  `email` 
**folder** |  optional  | Folder Name/Path \(to search in\) | string |  `mail folder`  `mail folder path` 
**subject** |  optional  | Substring to search in Subject | string | 
**sender** |  optional  | Sender Email address to match | string |  `email` 
**body** |  optional  | Substring to search in Body | string | 
**internet\_message\_id** |  optional  | Internet Message ID | string |  `internet message id` 
**query** |  optional  | AQS string | string | 
**range** |  optional  | Email range to return \(min\_offset\-max\_offset\) | string | 
**ignore\_subfolders** |  optional  | Ignore subfolders | boolean | 
**is\_public\_folder** |  optional  | Mailbox folder is a public folder | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.folder | string |  `mail folder`  `mail folder path` 
action\_result\.parameter\.ignore\_subfolders | boolean | 
action\_result\.parameter\.internet\_message\_id | string |  `internet message id` 
action\_result\.parameter\.is\_public\_folder | boolean | 
action\_result\.parameter\.query | string | 
action\_result\.parameter\.range | string | 
action\_result\.parameter\.sender | string |  `email` 
action\_result\.parameter\.subject | string | 
action\_result\.data\.\*\.folder | string |  `mail folder` 
action\_result\.data\.\*\.folder\_path | string |  `mail folder path` 
action\_result\.data\.\*\.t\_DateTimeReceived | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_EmailAddress | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_InternetMessageId | string |  `internet message id` 
action\_result\.data\.\*\.t\_ItemId\.\@ChangeKey | string | 
action\_result\.data\.\*\.t\_ItemId\.\@Id | string |  `exchange email id` 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_EmailAddress | string | 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_Subject | string | 
action\_result\.summary\.emails\_matched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete email'
Delete emails

Type: **contain**  
Read only: **False**

This action supports a comma separated list of message IDs as input\. This results in multiple emails getting deleted in a single call to the server\. If impersonation is enabled on the asset, the <b>email</b> parameter is required, else <b>email</b> will be ignored\.<br>The action requires the exchange email ID as input\. Many times this value is not easily available, since not many email clients display it\. However every email header has a value called <b>Message\-ID</b> assigned to it\. It's usually something like &lt;tS10Ncty2SyeJsjdNMsxV\+dguQ\+jd7RwiFgmZsLN\@contoso\.com&gt;\. Use this <b>Internet Message ID</b> as input to the <b>run query</b> action to get the <b>exchange email ID</b> of an email\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message IDs to delete \(comma separated values supported\) | string |  `exchange email id` 
**email** |  optional  | Email of the mailbox owner \(used during impersonation\) | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.id | string |  `exchange email id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'copy email'
Copy an email to a folder

Type: **generic**  
Read only: **False**

The action supports copying to a folder that is nested within another\.<br>To copy to such a folder, specify the complete path using the <b>'/'</b> \(forward slash\) as the separator\.<br>For example, to copy email to a folder named <i>phishing</i> which is nested within <i>Inbox</i>, set the value as <b>Inbox/phishing</b>\.<br>The action requires the exchange email ID as input\. Many times this value is not easily available, since not many email clients display it\. However every email header has a value called <b>Message\-ID</b> assigned to it\. It's usually something like &lt;tS10Ncty2SyeJsjdNMsxV\+dguQ\+jd7RwiFgmZsLN\@contoso\.com&gt;\. Use this <b>Internet Message ID</b> as input to the <b>run query</b> action to get the <b>exchange email ID</b> of an email\.<br>The action will return the ID of the newly copied email in the data path <b>action\_result\.data\.\*\.new\_email\_id</b>, however this value is not available for cross\-mailbox or mailbox to public folder <b>copy email</b> actions \(please see the documentation of the <a href="https\://msdn\.microsoft\.com/en\-us/library/office/aa565012\(v=exchg\.150\)\.aspx">CopyItem operation on MSDN</a>\)\. However in such scenarios, do a <b>run query</b> on the new mailbox plus folder with a specific parameter like <b>Internet Message ID</b> to get the <b>Exchange email ID</b>\.<br><br><b>Impersonation</b><p>Impersonation plays a big role in the <b>copy email</b> action, for reasons explained in this section, <b>copy email</b> is the only action that overrides the asset config parameter <b>use\_impersonation</b>\. By default, the action will <i>impersonate</i> the user specified in the <b>email</b> parameter, if impersonation is enabled \(by setting the <b>dont\_impersonate</b> action parameter to False or Unchecked\)\.<br>However depending on the server configuration, this action might fail with an <i>Access Denied</i> error\. If an email is being copied from one folder to another in the same mailbox, the action will succeed, however if the email is being copied from one mailbox's folder to a different mailbox, the impersonated user will require access to both the mailboxes\. In this case the action might require to impersonate a user other than the one specified in the <b>email</b> parameter\. In such a scenario use the <b>impersonate\_email</b> to specify an alternate email to <i>impersonate</i>\.<br>Set the <b>dont\_impersonate</b> parameter to <b>True</b> to disable impersonation all together\. This value will override the one configured on the asset\. The default value of this param is <b>False</b>\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to copy | string |  `exchange email id` 
**email** |  required  | Destination Mailbox \(Email\) | string |  `email` 
**folder** |  required  | Destination Mail Folder Name/Path | string |  `mail folder`  `mail folder path` 
**impersonate\_email** |  optional  | Impersonation Email | string |  `email` 
**dont\_impersonate** |  optional  | Don't use impersonation | boolean | 
**is\_public\_folder** |  optional  | Mailbox folder is a public folder | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.dont\_impersonate | boolean | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.folder | string |  `mail folder`  `mail folder path` 
action\_result\.parameter\.id | string |  `exchange email id` 
action\_result\.parameter\.impersonate\_email | string |  `email` 
action\_result\.parameter\.is\_public\_folder | boolean | 
action\_result\.data\.\*\.new\_email\_id | string |  `exchange email id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'move email'
Move an email to a folder

Type: **generic**  
Read only: **False**

The action supports moving an email to a folder that is nested within another\.<br>To move to such a folder, specify the complete path using the <b>'/'</b> \(forward slash\) as the separator\.<br>For example, to move email to a folder named <i>phishing</i> which is nested within <i>Inbox</i>, set the value as <b>Inbox/phishing</b>\.<br>The action requires the exchange email ID as input\. Many times this value is not easily available, since not many email clients display it\. However every email header has a value called <b>Message\-ID</b> assigned to it\. It's usually something like &lt;tS10Ncty2SyeJsjdNMsxV\+dguQ\+jd7RwiFgmZsLN\@contoso\.com&gt;\. Use this <b>Internet Message ID</b> as input to the <b>run query</b> action to get the <b>exchange email ID</b> of an email\.<br>The action will return the ID of the newly copied email in the data path <b>action\_result\.data\.\*\.new\_email\_id</b>, however this value is not available for cross\-mailbox or mailbox to public folder <b>move email</b> actions \(please see the documentation of the <a href="https\://msdn\.microsoft\.com/en\-us/library/office/aa565012\(v=exchg\.150\)\.aspx">MoveItem operation on MSDN</a>\)\. However in such scenarios, do a <b>run query</b> on the new mailbox plus folder with a specific parameter like <b>Internet Message ID</b> to get the <b>Exchange email ID</b>\.<br><br><b>Impersonation</b><p>Impersonation plays a big role in the <b>move email</b> action, for reasons explained in this section, <b>move email</b> is the only action that overrides the asset config parameter <b>use\_impersonation</b>\. By default, the action will <i>impersonate</i> the user specified in the <b>email</b> parameter, if impersonation is enabled \(by setting the <b>dont\_impersonate</b> action parameter to False or Unchecked\)\.<br>However depending on the server configuration, this action might fail with an <i>Access Denied</i> error\. If an email is being copied from one folder to another in the same mailbox, the action will succeed, however if the email is being copied from one mailbox's folder to a different mailbox, the impersonated user will require access to both the mailboxes\. In this case the action might require to impersonate a user other than the one specified in the <b>email</b> parameter\. In such a scenario use the <b>impersonate\_email</b> to specify an alternate email to <i>impersonate</i>\.<br>Set the <b>dont\_impersonate</b> parameter to <b>True</b> to disable impersonation all together\. This value will override the one configured on the asset\. The default value of this param is <b>False</b>\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to move | string |  `exchange email id` 
**email** |  required  | Destination Mailbox \(Email\) | string |  `email` 
**folder** |  required  | Destination Mail Folder Name/Path | string |  `mail folder`  `mail folder path` 
**impersonate\_email** |  optional  | Impersonation Email | string |  `email` 
**dont\_impersonate** |  optional  | Don't use impersonation | boolean | 
**is\_public\_folder** |  optional  | Mailbox folder is a public folder | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.dont\_impersonate | boolean | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.folder | string |  `mail folder`  `mail folder path` 
action\_result\.parameter\.id | string |  `exchange email id` 
action\_result\.parameter\.impersonate\_email | string |  `email` 
action\_result\.parameter\.is\_public\_folder | boolean | 
action\_result\.data\.\*\.new\_email\_id | string |  `exchange email id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get email'
Get an email from the server

Type: **investigate**  
Read only: **True**

Every container that is created by the app has the following values\:<ul><li>The container ID that is generated by the Phantom platform\.</li><li>The Source ID that the app equates to the email ID on the server if known or the vault ID if asked to parse from the vault\.</li><li>The raw\_email data in the container's data field is set to the RFC822 format of the email\.</li></ul>This action parses email data and if specified creates containers and artifacts\. The email data to parse is either extracted from the remote server if an email ID is specified, from a Phantom container, if the <b>container\_id</b> is specified or from the vault item if the <b>vault\_id</b> is specified\.<br>If all three parameters are specified, the action will use the <b>container\_id</b>\.<br>The data paths differ depending on where the email data is parsed from\.<br><br><p>If parsed from the server\:<br><ul><li>The data path <b>action\_result\.data\.\*\.t\_MimeContent\.\#text</b> contains the email in RFC822 format, but base64 encoded\.</li><li>The data path <b>action\_result\.data\.\*\.t\_Body\.\#text</b> contains the email body\.</li><li>The widget for this action will render a text version of the email body if possible\.</li><li>If impersonation is enabled on the asset, the <b>email</b> parameter is required, else <b>email</b> will be ignored\.</li></ul></p><p>If parsed from the container or vault\:<br><ul><li>The widget does not render the email body\.</li><li>The email headers are listed in a table\.</li></ul></p><p>If <b>ingest\_email</b> is set to </b>True</b>\:<br><ul><li>The ID of the container created or updated will be set in the <b>action\_result\.summary\.container\_id</b> data path\.</li><li>The widget will display this ID as <b>Ingested Container ID</b>\.</li></ul></p>Do note that any containers and artifacts created will use the label configured in the asset\.<br>The action will fail if the vault item asked to parse and ingest is not an email item \(\.eml\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  optional  | Message ID to get | string |  `exchange email id` 
**email** |  optional  | Email of the mailbox owner \(used during impersonation\) | string |  `email` 
**container\_id** |  optional  | Container ID to get email data from | numeric |  `phantom container id` 
**vault\_id** |  optional  | Vault ID to get email from | string |  `vault id` 
**ingest\_email** |  optional  | Create containers and artifacts | boolean | 
**use\_current\_container** |  optional  | Create artifacts in the same container | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | numeric |  `phantom container id` 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.id | string |  `exchange email id` 
action\_result\.parameter\.ingest\_email | boolean | 
action\_result\.parameter\.use\_current\_container | boolean | 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.CC | string | 
action\_result\.data\.\*\.Content\-Language | string | 
action\_result\.data\.\*\.Content\-Type | string | 
action\_result\.data\.\*\.Date | string | 
action\_result\.data\.\*\.Delivered\-To | string | 
action\_result\.data\.\*\.From | string | 
action\_result\.data\.\*\.Importance | string | 
action\_result\.data\.\*\.MIME\-Version | string | 
action\_result\.data\.\*\.Mail\-Filter\-Gateway | string | 
action\_result\.data\.\*\.Message\-ID | string |  `internet message id` 
action\_result\.data\.\*\.Received | string | 
action\_result\.data\.\*\.Return\-Path | string | 
action\_result\.data\.\*\.Sender | string | 
action\_result\.data\.\*\.Subject | string | 
action\_result\.data\.\*\.Thread\-Index | string | 
action\_result\.data\.\*\.Thread\-Topic | string | 
action\_result\.data\.\*\.To | string | 
action\_result\.data\.\*\.X\-Account\-Key | string | 
action\_result\.data\.\*\.X\-CTCH\-RefID | string | 
action\_result\.data\.\*\.X\-MS\-Exchange\-Organization\-RecordReviewCfmType | string | 
action\_result\.data\.\*\.X\-MS\-Exchange\-Organization\-SCL | string | 
action\_result\.data\.\*\.X\-MS\-Has\-Attach | string | 
action\_result\.data\.\*\.X\-MS\-TNEF\-Correlator | string | 
action\_result\.data\.\*\.X\-Mail\-Filter\-Gateway\-From | string |  `email` 
action\_result\.data\.\*\.X\-Mail\-Filter\-Gateway\-ID | string | 
action\_result\.data\.\*\.X\-Mail\-Filter\-Gateway\-SpamDetectionEngine | string | 
action\_result\.data\.\*\.X\-Mail\-Filter\-Gateway\-SpamScore | string | 
action\_result\.data\.\*\.X\-Mail\-Filter\-Gateway\-To | string |  `email` 
action\_result\.data\.\*\.X\-Mailer | string | 
action\_result\.data\.\*\.X\-MimeOLE | string | 
action\_result\.data\.\*\.X\-Mozilla\-Keys | string | 
action\_result\.data\.\*\.X\-Priority | string | 
action\_result\.data\.\*\.X\-SOHU\-Antispam\-Bayes | string | 
action\_result\.data\.\*\.X\-SOHU\-Antispam\-Language | string | 
action\_result\.data\.\*\.X\-Spam\-Status | string | 
action\_result\.data\.\*\.X\-UIDL | string | 
action\_result\.data\.\*\.decodedSubject | string | 
action\_result\.data\.\*\.t\_AdjacentMeetingCount | string | 
action\_result\.data\.\*\.t\_AssociatedCalendarItemId\.\@ChangeKey | string | 
action\_result\.data\.\*\.t\_AssociatedCalendarItemId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_AttachmentId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_ContentId | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_ContentType | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_IsContactPhoto | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_IsInline | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.\*\.t\_Size | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_AttachmentId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_ContentId | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_ContentType | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_IsContactPhoto | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_IsInline | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_Size | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.\*\.t\_AttachmentId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.\*\.t\_IsInline | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.\*\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.\*\.t\_Name | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.\*\.t\_Size | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_AttachmentId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_ContentId | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_ContentType | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_IsInline | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_Name | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_ItemAttachment\.t\_Size | string | 
action\_result\.data\.\*\.t\_Body\.\#text | string | 
action\_result\.data\.\*\.t\_Body\.\@BodyType | string | 
action\_result\.data\.\*\.t\_Body\.\@IsTruncated | string | 
action\_result\.data\.\*\.t\_Categories\.t\_String | string | 
action\_result\.data\.\*\.t\_CcRecipients\.t\_Mailbox\.t\_EmailAddress | string | 
action\_result\.data\.\*\.t\_CcRecipients\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_CcRecipients\.t\_Mailbox\.t\_Name | string | 
action\_result\.data\.\*\.t\_CcRecipients\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_ConflictingMeetingCount | string | 
action\_result\.data\.\*\.t\_DateTimeCreated | string | 
action\_result\.data\.\*\.t\_DateTimeReceived | string | 
action\_result\.data\.\*\.t\_DateTimeSent | string | 
action\_result\.data\.\*\.t\_End | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.\*\.t\_ExtendedFieldURI\.\@PropertyTag | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.\*\.t\_ExtendedFieldURI\.\@PropertyType | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.\*\.t\_Value | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.t\_ExtendedFieldURI\.\@PropertyTag | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.t\_ExtendedFieldURI\.\@PropertyType | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.t\_Value | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_HasAttachments | string | 
action\_result\.data\.\*\.t\_HasBeenProcessed | string | 
action\_result\.data\.\*\.t\_IntendedFreeBusyStatus | string | 
action\_result\.data\.\*\.t\_InternetMessageId | string |  `internet message id` 
action\_result\.data\.\*\.t\_IsAssociated | string | 
action\_result\.data\.\*\.t\_IsDelegated | string | 
action\_result\.data\.\*\.t\_IsDeliveryReceiptRequested | string | 
action\_result\.data\.\*\.t\_IsOutOfDate | string | 
action\_result\.data\.\*\.t\_IsRead | string | 
action\_result\.data\.\*\.t\_IsReadReceiptRequested | string | 
action\_result\.data\.\*\.t\_ItemId\.\@ChangeKey | string | 
action\_result\.data\.\*\.t\_ItemId\.\@Id | string | 
action\_result\.data\.\*\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Location | string | 
action\_result\.data\.\*\.t\_MeetingRequestType | string | 
action\_result\.data\.\*\.t\_MimeContent\.\#text | string | 
action\_result\.data\.\*\.t\_MimeContent\.\@CharacterSet | string | 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_ResponseType | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_AcceptItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_DeclineItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ForwardItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ProposeNewTime | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ReplyAllToItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ReplyToItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_TentativelyAcceptItem | string | 
action\_result\.data\.\*\.t\_ResponseType | string | 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_Sensitivity | string | 
action\_result\.data\.\*\.t\_Size | string | 
action\_result\.data\.\*\.t\_Start | string | 
action\_result\.data\.\*\.t\_Subject | string | 
action\_result\.data\.\*\.t\_TextBody\.\#text | string | 
action\_result\.data\.\*\.t\_TextBody\.\@BodyType | string | 
action\_result\.data\.\*\.t\_TextBody\.\@IsTruncated | string | 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_RoutingType | string | 
action\_result\.summary\.container\_id | numeric |  `phantom container id` 
action\_result\.summary\.create\_time | string | 
action\_result\.summary\.email\_id | numeric |  `exchange email id` 
action\_result\.summary\.sent\_time | string | 
action\_result\.summary\.subject | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list addresses'
Get the email addresses that make up a Distribution List

Type: **investigate**  
Read only: **True**

The <b>group</b> parameter supports, as input, the email \(for e\.g\. dleng\@corp\.contoso\.com\) or the name \(for e\.g\. dleng\) of the distribution list\.<br><br>The <b>recursive</b> parameter will cause the action to recursively search for distribution lists inside of the initial distribution lists and expand those\.<br>Each discovered distribution list will be submitted as a separate set of results, causing multiple sets of action results to be created\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** |  required  | Distribution List to expand | string |  `email`  `exchange distribution list`  `user name` 
**recursive** |  optional  | Expand all sub distribution lists | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group | string |  `email`  `exchange distribution list`  `user name` 
action\_result\.parameter\.recursive | boolean | 
action\_result\.data\.\*\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_RoutingType | string | 
action\_result\.summary\.total\_entries | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup email'
Resolve an Alias name or email address, into mailboxes

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Name to resolve | string |  `exchange alias`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `exchange alias`  `email` 
action\_result\.data\.\*\.t\_Contact\.t\_AssistantName | string | 
action\_result\.data\.\*\.t\_Contact\.t\_CompanyName | string | 
action\_result\.data\.\*\.t\_Contact\.t\_ContactSource | string | 
action\_result\.data\.\*\.t\_Contact\.t\_Culture | string | 
action\_result\.data\.\*\.t\_Contact\.t\_Department | string | 
action\_result\.data\.\*\.t\_Contact\.t\_DisplayName | string | 
action\_result\.data\.\*\.t\_Contact\.t\_EmailAddresses\.\*\.\#text | string | 
action\_result\.data\.\*\.t\_Contact\.t\_EmailAddresses\.\*\.\@Key | string | 
action\_result\.data\.\*\.t\_Contact\.t\_GivenName | string | 
action\_result\.data\.\*\.t\_Contact\.t\_Initials | string | 
action\_result\.data\.\*\.t\_Contact\.t\_JobTitle | string | 
action\_result\.data\.\*\.t\_Contact\.t\_Manager | string | 
action\_result\.data\.\*\.t\_Contact\.t\_OfficeLocation | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhoneNumbers\.t\_Entry\.\*\.\#text | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhoneNumbers\.t\_Entry\.\*\.\@Key | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhysicalAddresses\.t\_Entry\.\@Key | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhysicalAddresses\.t\_Entry\.t\_City | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhysicalAddresses\.t\_Entry\.t\_CountryOrRegion | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhysicalAddresses\.t\_Entry\.t\_PostalCode | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhysicalAddresses\.t\_Entry\.t\_State | string | 
action\_result\.data\.\*\.t\_Contact\.t\_PhysicalAddresses\.t\_Entry\.t\_Street | string | 
action\_result\.data\.\*\.t\_Contact\.t\_Surname | string | 
action\_result\.data\.\*\.t\_Mailbox\.t\_EmailAddress | string | 
action\_result\.data\.\*\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.summary\.total\_entries | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update email'
Update an email on the server

Type: **generic**  
Read only: **False**

Currently this action only updates the category and subject of an email\. To set multiple categories, please pass a comma separated list to the <b>category</b> parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to update | string |  `exchange email id` 
**email** |  optional  | Email of the mailbox owner \(used during impersonation\) | string |  `email` 
**subject** |  optional  | Subject to set | string | 
**category** |  optional  | Categories to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.category | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.id | string |  `exchange email id` 
action\_result\.parameter\.subject | string | 
action\_result\.data\.\*\.t\_AdjacentMeetingCount | string | 
action\_result\.data\.\*\.t\_AssociatedCalendarItemId\.\@ChangeKey | string | 
action\_result\.data\.\*\.t\_AssociatedCalendarItemId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_AttachmentId\.\@Id | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_ContentId | string |  `email` 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_ContentType | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_IsContactPhoto | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_IsInline | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Attachments\.t\_FileAttachment\.t\_Size | string | 
action\_result\.data\.\*\.t\_Body\.\#text | string | 
action\_result\.data\.\*\.t\_Body\.\@BodyType | string | 
action\_result\.data\.\*\.t\_Body\.\@IsTruncated | string | 
action\_result\.data\.\*\.t\_Categories | string | 
action\_result\.data\.\*\.t\_ConflictingMeetingCount | string | 
action\_result\.data\.\*\.t\_DateTimeCreated | string | 
action\_result\.data\.\*\.t\_DateTimeReceived | string | 
action\_result\.data\.\*\.t\_DateTimeSent | string | 
action\_result\.data\.\*\.t\_End | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.t\_ExtendedFieldURI\.\@PropertyTag | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.t\_ExtendedFieldURI\.\@PropertyType | string | 
action\_result\.data\.\*\.t\_ExtendedProperty\.t\_Value | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_From\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_HasAttachments | string | 
action\_result\.data\.\*\.t\_HasBeenProcessed | string | 
action\_result\.data\.\*\.t\_IntendedFreeBusyStatus | string | 
action\_result\.data\.\*\.t\_InternetMessageId | string | 
action\_result\.data\.\*\.t\_IsAssociated | string | 
action\_result\.data\.\*\.t\_IsDelegated | string | 
action\_result\.data\.\*\.t\_IsDeliveryReceiptRequested | string | 
action\_result\.data\.\*\.t\_IsOutOfDate | string | 
action\_result\.data\.\*\.t\_IsRead | string | 
action\_result\.data\.\*\.t\_IsReadReceiptRequested | string | 
action\_result\.data\.\*\.t\_ItemId\.\@ChangeKey | string | 
action\_result\.data\.\*\.t\_ItemId\.\@Id | string | 
action\_result\.data\.\*\.t\_LastModifiedTime | string | 
action\_result\.data\.\*\.t\_Location | string | 
action\_result\.data\.\*\.t\_MeetingRequestType | string | 
action\_result\.data\.\*\.t\_MimeContent\.\#text | string | 
action\_result\.data\.\*\.t\_MimeContent\.\@CharacterSet | string | 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Organizer\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_RequiredAttendees\.t\_Attendee\.\*\.t\_ResponseType | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_AcceptItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_DeclineItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ForwardItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ProposeNewTime | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ReplyAllToItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_ReplyToItem | string | 
action\_result\.data\.\*\.t\_ResponseObjects\.t\_TentativelyAcceptItem | string | 
action\_result\.data\.\*\.t\_ResponseType | string | 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_Sender\.t\_Mailbox\.t\_RoutingType | string | 
action\_result\.data\.\*\.t\_Sensitivity | string | 
action\_result\.data\.\*\.t\_Size | string | 
action\_result\.data\.\*\.t\_Start | string | 
action\_result\.data\.\*\.t\_Subject | string | 
action\_result\.data\.\*\.t\_TextBody\.\#text | string | 
action\_result\.data\.\*\.t\_TextBody\.\@BodyType | string | 
action\_result\.data\.\*\.t\_TextBody\.\@IsTruncated | string | 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_EmailAddress | string |  `email` 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_MailboxType | string | 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_Name | string |  `user name` 
action\_result\.data\.\*\.t\_ToRecipients\.t\_Mailbox\.\*\.t\_RoutingType | string | 
action\_result\.summary\.create\_time | string | 
action\_result\.summary\.sent\_time | string | 
action\_result\.summary\.subject | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Ingest emails from the server into Phantom

Type: **ingest**  
Read only: **True**

Please see sections <a href="\#poll\_now">POLL NOW</a> and <a href="\#scheduled\_polling">Scheduled Polling</a> for more info on how this action is implemented by the app\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter Ignored in this app | numeric | 
**end\_time** |  optional  | Parameter Ignored in this app | numeric | 
**container\_id** |  optional  | Parameter Ignored in this app | numeric | 
**container\_count** |  required  | Maximum number of emails to ingest | numeric | 
**artifact\_count** |  optional  | Parameter Ignored in this app | numeric | 

#### Action Output
No Output