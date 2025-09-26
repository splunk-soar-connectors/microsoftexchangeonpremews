# Microsoft Exchange On-Premise EWS

Publisher: Splunk <br>
Connector Version: 3.13.5 <br>
Product Vendor: Microsoft <br>
Product Name: Exchange <br>
Minimum Product Version: 6.2.1

This app performs email ingestion, investigative and containment actions on an on-premise Exchange installation

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

- EWS URL: The URL configured by the person that set up the Exchange server.
- EWS Version: Ensure the version in the dropdown corresponds to the version of Exchange you have
  installed.
- Username and Password: Use the username and password that have the correct privileges to access
  other mailboxes.
- (Optional) User Email Mailbox: The mailbox you will ingest data from if you use polling and to
  test connectivity.
- (Optional) Script with functions to preprocess containers and artifacts: The user can add a
  script file in the configuration parameter. The script must contain a function with the name
  **preprocess_container** (to pre-process the containers and the artifacts) else it will throw an
  error. The script should not contain **run_automation** (or any other logic to trigger active
  playbooks) since the app automatically handles the triggering. The implementation will first
  process the container according to the script and save it. The artifacts are then added to the
  container, processed, and saved in that order. Hence, when adding a script to process artifacts,
  verify if artifacts are present in the container before modifying them.
- On poll information: Configure your desired on poll settings. For example, how to ingest, the
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

**Note:**

- "Mailbox folder to be polled" parameter is case-sensitive.
- The "Container Severity" value set in the asset configuration parameter will be applicable to
  the container as well as all the artifacts created inside the container.

## Scheduled Polling

This mode is used to schedule a polling action on the asset at regular intervals, which is
configured via the INGEST SETTINGS tab of the asset. It makes use of the following asset
configuration parameters (among others):

- Maximum emails to poll the first time

  The app detects the first time it is polling an asset and will ingest this number of emails (at
  the most).

- Maximum emails to poll

  For all scheduled polls after the first, the app will ingest this number of emails.

- How to ingest

  Should the app be ingesting the latest emails or the oldest.

In the case of Scheduled Polling, on every poll, the app remembers the last email that it has
ingested and will pick up from the next one in the next scheduled poll.

### How to ingest

The app allows the user to configure how it should ingest emails on every scheduled poll either in
the *oldest first* or the *latest first* order. Depending upon the scheduled interval and how busy
the folder is, one of the following could potentially happen

- oldest first

  If the app is configured to poll too slowly and the folder is so busy that on every poll the
  maximum ingested emails is less than the number of new emails, the app will never catch up.

- latest first

  If the app is configured to poll too slowly and the folder is so busy that on every poll the
  maximum ingested emails is less than the number of new emails, the app will drop the older
  emails since it is ingesting the latest emails that came into the mailbox.

For best results, keep the poll interval and *Maximum emails to poll* values close to the number of
emails you would get within a time interval. This way, every poll will end up ingesting all the new
emails.

### Sort mails by

This parameter defines on which email attribute, the order *latest first* / *oldest first* should be
applied. The user can configure it to any of the below values.

- updated time

  The application will fetch and ingest emails with the latest updated time field of the email
  attribute.

- created time

  The application will fetch and ingest emails with the created time field of the email attribute.
  Be careful while using this option, as the application fetches the emails by the created time,
  any update made on the email after ingestion, will not be reflected in the phantom container.

In case the asset is configured to poll **oldest first** , it becomes important that the *Maximum
number of emails to poll* configured should be greater than the maximum number of emails generated
**per second** . If the app detects it got the maximum configured emails and all occurred in the
same second, it will start polling from the next second in the next polling cycle.

### Save raw email content to container

This asset configuration parameter determines whether or not the raw email content of the ingested
email will be saved to the container. If the box is checked, the raw email data will be saved to the
**data** dictionary. The default setting is TRUE.

### Run automation on duplicate event

Set this parameter to run the automation, when there is a modification in the email which is already
ingested. If you don't want to trigger the automation for such small changes (in case of
re-ingestion), this parameter can be set to FALSE.

## Important points regarding scheduled polling

- The accuracy of "scheduled polling" can't be assured for lower polling intervals. The variance
  of +/-2 minutes is acceptable in the current implementation.

- The interval period must be set considering various aspects. Anything below 5 minutes can be
  considered as less accurate.

- One can separate out the mail boxes to increase the accuracy of polling. For example, inbox,
  drafts and other folders. This allows multiple ingestions on different assets by keeping longer
  interval period (i.e. 5 minutes), rather than a single asset with 1 minute interval period.

- When the ingestion time takes longer than the interval period( i.e. When the interval period is
  1-minute, and it takes 2 minutes to ingest an email), In this case, the following scenarios are
  possible.

  - The timing can not be exact, as one ingestion must complete before the timer is resumed.
  - It is also possible that even after turning off the scheduled polling, some emails would be
    ingested as the emails are queued when the ingestion takes longer than the period.
  - Hence, it is important to set the appropriate ingestion period as per your data.

## Artifacts created

The app will create the following type of artifacts:

- Email Artifact

  The email addresses that are found in the ingested email will be added as a separate artifact.
  Any attached email will also be scanned and the address present in the attached email will be
  added as a separate artifact. The emails are added as custom strings in the CEF structure in the
  following manner.

  | **Artifact Field** | **Value Details** |
  |--------------------|-----------------------------------------------------------------------------------|
  | fromEmail | The email address of the sender |
  | toEmail | The email address of the receiver of the email |
  | emailHeaders | A dictionary containing each email header as a key and its value as the key-value |

  [![](img/email_artifact.png)](img/email_artifact.png)

- IP Artifact - cef.sourceAddress

  - If **extract_ips** is enabled, any IPv4 or IPv6 found in the email body will be added, with
    one CEF per IP.
  - Any IP addresses found in the email are added to the CEF structure of an artifact.
  - The CEF for an IP is cef.sourceAddress.

- Hash Artifact - cef.fileHash

  - If **extract_hashes** is enabled, any hash found in the email body will be added, with one
    CEF per hash.
  - Any Hashes found in the email are added to the CEF structure of an artifact.
  - The CEF for a hash is cef.fileHash.

- URL Artifact - cef.requestURL

  - If **extract_urls** is enabled, any URL found in the email body will be added, with one CEF
    per url.
  - Any URLs or hyperlinks found are added to the CEF structure of an artifact.
  - The CEF for a URL is cef.requestURL.

- Domain Artifact - cef.destinationDnsDomain

  - If **extract_domains** is enabled, any domain found in the email body will be added, with
    one CEF per domain.
  - Domains that are part of a URL, a hyperlink or an email address are added to the CEF
    structure of an artifact.
  - The CEF for a Domain is cef.destinationDnsDomain.

- Vault Artifact

  - If the email contains any attachments, these are extracted (if **extract_attachments** is
    enabled) and added to the vault of the Container.
  - At the same time, the vault ID and file name of this item is represented by a Vault
    Artifact.
  - Some special characters will be removed from the file name before ingestion. Such as
    comma(,), single quote(') and double quote(").
  - The same file can be added to the vault multiple times. In this scenario, the file name of
    the item added the second time onwards will be slightly different, but the vault ID will
    still be the same. However, there will be multiple artifacts created.
  - Do note that the system does *not* duplicate the file bytes, only the metadata in the
    database.
    | **Artifact Field** | **Value Details** |
    |--------------------|----------------------------------------------------------------------------------|
    | Source ID | Email ID set on the server |
    | cef.vaultId | Vault ID of the attachment |
    | cef.fileHashMd5 | MD5 hash of the attachment |
    | cef.fileHashSha1 | SHA1 hash of the attachment |
    | cef.fileHashSha256 | SHA256 hash of the attachment |
    | cef.fileName | File name of the attachment |
    | cef.headers | A dictionary containing each file header as a key and its value as the key-value |
  - You will notice additional CEF fields **cs6** (value is the Vault ID) and **cs6Label** .
    These are added for backward compatibility only and will be deprecated in future releases.
    Please don't use these keys in playbooks.

  [![](img/vault_artifact.png)](img/vault_artifact.png)

## Copy Email

To use the copy email command, follow these steps:

1. Navigate to the Investigation page.
1. Click **Action** .
1. In the search bar, search for the copy email command.
1. Click **copy email** .
1. Click **exchange,** or whatever asset name you created, as the asset you want to run the **copy
   email** command on.
1. Enter the ID. Each email in Exchange has a unique ID. You can get this email ID from an email
   artifact that was previously ingested, or by running a run query action.
1. Enter the email address of the user you want to copy the email from and the folder you want to
   copy the email to.
1. From the message ID, click the drop down arrow and click **Run Action** .
1. Enter the email and the folder you want to move it to.
1. Click **Launch** .

### Preprocessing Containers

It is possible to upload your own script which has functions to handle preprocessing of containers.
The artifacts which are going to be added with the container can be accessed through this container
as well. This function should accept a container and return the updated container. Also note that
the name of this function must be **preprocess_container** .

```shell
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

The app uses the HTTP/HTTPS protocol for communicating with the Microsoft Exchange On-Premise EWS
Server. Below are the default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

## Playbook Backward Compatibility

With this release, we are removing the asset parameter 'unify_cef_fields', and the CC and BCC CEF
fields will be in uppercase only. In order to avoid confusion, playbooks that use these CEF fields
in lowercase should be updated to uppercase.

### Configuration variables

This table lists the configuration variables required to operate Microsoft Exchange On-Premise EWS. These variables are specified when configuring a Exchange asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | EWS URL |
**version** | optional | string | EWS Version |
**verify_server_cert** | optional | boolean | Verify server certificate |
**username** | required | string | Username |
**password** | required | password | Password |
**poll_user** | optional | string | User Email Mailbox (Test Connectivity and Poll) |
**use_impersonation** | optional | boolean | Use Impersonation |
**poll_folder** | required | string | Mailbox folder to be polled |
**is_public_folder** | optional | boolean | Mailbox folder is a public folder |
**first_run_max_emails** | required | numeric | Maximum emails to poll first time |
**max_containers** | required | numeric | Maximum emails for scheduled polling |
**ingest_manner** | required | string | How to ingest |
**container_severity** | optional | string | Container Severity |
**ingest_time** | optional | string | Sort mails by |
**extract_attachments** | optional | boolean | Extract Attachments |
**extract_urls** | optional | boolean | Extract URLs |
**extract_ips** | optional | boolean | Extract IPs |
**extract_domains** | optional | boolean | Extract Domain Names |
**extract_hashes** | optional | boolean | Extract Hashes |
**extract_email_addresses** | optional | boolean | Extract Email Addresses |
**add_body_to_header_artifacts** | optional | boolean | Add email body to the Email Artifact |
**extract_root_email_as_vault** | optional | boolean | Extract root (primary) email as Vault |
**save_raw_email_to_container** | optional | boolean | Save raw email to container data dictionary |
**preprocess_script** | optional | file | Script with functions to preprocess containers and artifacts |
**automation_on_duplicate** | optional | boolean | Run automation on duplicate event |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[run query](#action-run-query) - Search emails <br>
[delete email](#action-delete-email) - Delete emails <br>
[copy email](#action-copy-email) - Copy an email to a folder <br>
[move email](#action-move-email) - Move an email to a folder <br>
[get email](#action-get-email) - Get an email from the server <br>
[list addresses](#action-list-addresses) - Get the email addresses that make up a Distribution List <br>
[lookup email](#action-lookup-email) - Resolve an Alias name or email address, into mailboxes <br>
[update email](#action-update-email) - Update an email on the server <br>
[on poll](#action-on-poll) - Ingest emails from the server into Splunk SOAR

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'run query'

Search emails

Type: **investigate** <br>
Read only: **True**

The <b>run query</b> action provides more than one method to search a user's mailbox:<br><ul><li>Simple Search<br>Use the <b>subject</b> and <b>body</b> parameters to search for substring matches. The <b>sender</b> parameter can be used to search for emails from a specific address. However it has been noticed that a match with the <b>sender</b> email address fails for emails that have been never sent or received, but instead have been created manually as a draft and copied to the searched mailbox. In such cases an AQS is a better option. If more than one parameter is specified, the search is an <b>And</b> of the given values including the <b>internet_message_id</b>.<br> <b>Simple Search</b> implements search filters. More details regarding search filters can be found on this <a href="https://msdn.microsoft.com/en-us/library/office/dn579422(v=exchg.150).aspx">MSDN Link</a>.<br></li><li>Query Search<br>For a more fine-grained email search, the use of the <b>query</b> parameter is recommended. If this parameter is specified, the <b>subject</b>, <b>sender</b>, <b>internet_message_id</b> and <b>body</b> parameters are ignored.<br>This parameter supports AQS queries to search in a Mailbox. More details regarding AQS keywords supported by Exchange can be found on this <a href="https://msdn.microsoft.com/en-us/library/office/dn579420(v=exchg.150).aspx">MSDN Link.</a><br>Searching with AQS strings does have one notable restriction, however. The AQS search string will only match substrings from the start of a word. If a substring needs to be found in the middle of a word, use a <b>Simple Search</b>.<br>Some examples:<br><ul><li>All emails from user1@contoso.com or user2@contoso.com<br>from:user1@contoso.com OR from:user2@contoso.com</li><li>All emails containing the string <i>free vacations</i><br>body: free vacations</li><li>This will match an email with subject containing the word <i>Details</i> but not <i>Cadet</i><br>subject:det</li></li></ul></ul>If the <b>folder</b> parameter is not specified, each email based folder such as Inbox, Sent etc. will be searched, including the children (nested) folders.<br>The action supports searching a folder that is nested within another.<br>To search in such a folder, specify the complete path using the <b>'/'</b> (forward slash) as the separator.<br>For e.g. to search in a folder named <i>phishing</i> which is nested within (a child of) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>.<br>NOTE: In some cases search results may return more emails than are visible in an email client. This is due to emails that have been just deleted, but not yet completely cleaned by the server.<br><br>The action supports limiting the number of emails returned using the <b>range</b> parameter. The input should be of the form <i>min_offset</i>-<i>max_offset</i>. The results are always sorted in <i>descending</i> order to place the latest emails at the top. For example to get the latest 10 emails that matched the filter, specify the range as 0-9. If multiple folders are searched for, then the range will be applied for each folder.<br>So if the folder being searched for example <i>Inbox</i> has a child (nested) folder called <i>phishing</i> and the range specified is 2-10, then the action will return 9 max emails for each folder. If the range parameter is not specified by default the action will use <b>0-10</b>.<br><br>NOTE: The <b>email</b> parameter is required.<br><br>Many actions such as <b>delete email</b> and <b>copy email</b> require the <b>exchange email ID</b> as input. Many times this value is not easily available, since not many email clients display it. However every email header has a value called <b>Message-ID</b> assigned to it. It's usually something like \<tS10Ncty2SyeJsjdNMsxV+dguQ+jd7RwiFgmZsLN@contoso.com>. Use this as the value (including the < and > chars if present) of <b>internet_message_id</b> parameter and execute the action. The results will contain the <b>exchange email ID</b> of an email, which can be used as input for other actions.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | required | User's Email (Mailbox to search in) | string | `email` |
**folder** | optional | Folder Name/Path (to search in) | string | `mail folder` `mail folder path` |
**subject** | optional | Substring to search in Subject | string | |
**sender** | optional | Sender Email address to match | string | `email` |
**body** | optional | Substring to search in Body | string | |
**internet_message_id** | optional | Internet Message ID | string | `internet message id` |
**query** | optional | AQS string | string | |
**range** | optional | Email range to return (min_offset-max_offset) | string | |
**ignore_subfolders** | optional | Ignore subfolders | boolean | |
**is_public_folder** | optional | Mailbox folder is a public folder | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.body | string | | Test body |
action_result.parameter.email | string | `email` | test@sample.com |
action_result.parameter.folder | string | `mail folder` `mail folder path` | Inbox |
action_result.parameter.ignore_subfolders | boolean | | True False |
action_result.parameter.internet_message_id | string | `internet message id` | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= |
action_result.parameter.is_public_folder | boolean | | True False |
action_result.parameter.query | string | | Subject: test subject |
action_result.parameter.range | string | | 0-10 |
action_result.parameter.sender | string | `email` | test@sample.com |
action_result.parameter.subject | string | | Important updates |
action_result.data.\*.folder | string | `mail folder` | Inbox |
action_result.data.\*.folder_path | string | `mail folder path` | |
action_result.data.\*.t_DateTimeReceived | string | | 2017-10-03T21:31:05Z |
action_result.data.\*.t_From.t_Mailbox.t_EmailAddress | string | | test@sample.com |
action_result.data.\*.t_From.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_From.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_From.t_Mailbox.t_RoutingType | string | | EX |
action_result.data.\*.t_InternetMessageId | string | `internet message id` | |
action_result.data.\*.t_ItemId.@ChangeKey | string | | |
action_result.data.\*.t_ItemId.@Id | string | `exchange email id` | |
action_result.data.\*.t_Sender.t_Mailbox.t_EmailAddress | string | | test@sample.com |
action_result.data.\*.t_Sender.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_Sender.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_Sender.t_Mailbox.t_RoutingType | string | | EX |
action_result.data.\*.t_Subject | string | | |
action_result.summary.emails_matched | numeric | | 1 |
action_result.message | string | | Emails matched: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete email'

Delete emails

Type: **contain** <br>
Read only: **False**

This action supports a comma separated list of message IDs as input. This results in multiple emails getting deleted in a single call to the server. If impersonation is enabled on the asset, the <b>email</b> parameter is required, else <b>email</b> will be ignored.<br>The action requires the exchange email ID as input. Many times this value is not easily available, since not many email clients display it. However every email header has a value called <b>Message-ID</b> assigned to it. It's usually something like \<tS10Ncty2SyeJsjdNMsxV+dguQ+jd7RwiFgmZsLN@contoso.com>. Use this <b>Internet Message ID</b> as input to the <b>run query</b> action to get the <b>exchange email ID</b> of an email.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message IDs to delete (comma separated values supported) | string | `exchange email id` |
**email** | optional | Email of the mailbox owner (used during impersonation) | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.email | string | `email` | test@sample.com |
action_result.parameter.id | string | `exchange email id` | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Email deleted |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'copy email'

Copy an email to a folder

Type: **generic** <br>
Read only: **False**

The action supports copying to a folder that is nested within another.<br>To copy to such a folder, specify the complete path using the <b>'/'</b> (forward slash) as the separator.<br>For example, to copy email to a folder named <i>phishing</i> which is nested within <i>Inbox</i>, set the value as <b>Inbox/phishing</b>.<br>The action requires the exchange email ID as input. Many times this value is not easily available, since not many email clients display it. However every email header has a value called <b>Message-ID</b> assigned to it. It's usually something like \<tS10Ncty2SyeJsjdNMsxV+dguQ+jd7RwiFgmZsLN@contoso.com>. Use this <b>Internet Message ID</b> as input to the <b>run query</b> action to get the <b>exchange email ID</b> of an email.<br>The action will return the ID of the newly copied email in the data path <b>action_result.data.\*.new_email_id</b>, however this value is not available for cross-mailbox or mailbox to public folder <b>copy email</b> actions (please see the documentation of the <a href="https://msdn.microsoft.com/en-us/library/office/aa565012(v=exchg.150).aspx">CopyItem operation on MSDN</a>). However in such scenarios, do a <b>run query</b> on the new mailbox plus folder with a specific parameter like <b>Internet Message ID</b> to get the <b>Exchange email ID</b>.<br><br><b>Impersonation</b><p>Impersonation plays a big role in the <b>copy email</b> action, for reasons explained in this section, <b>copy email</b> is the only action that overrides the asset config parameter <b>use_impersonation</b>. By default, the action will <i>impersonate</i> the user specified in the <b>email</b> parameter, if impersonation is enabled (by setting the <b>dont_impersonate</b> action parameter to False or Unchecked).<br>However depending on the server configuration, this action might fail with an <i>Access Denied</i> error. If an email is being copied from one folder to another in the same mailbox, the action will succeed, however if the email is being copied from one mailbox's folder to a different mailbox, the impersonated user will require access to both the mailboxes. In this case the action might require to impersonate a user other than the one specified in the <b>email</b> parameter. In such a scenario use the <b>impersonate_email</b> to specify an alternate email to <i>impersonate</i>.<br>Set the <b>dont_impersonate</b> parameter to <b>True</b> to disable impersonation all together. This value will override the one configured on the asset. The default value of this param is <b>False</b>.</p>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to copy | string | `exchange email id` |
**email** | required | Destination Mailbox (Email) | string | `email` |
**folder** | required | Destination Mail Folder Name/Path | string | `mail folder` `mail folder path` |
**impersonate_email** | optional | Impersonation Email | string | `email` |
**dont_impersonate** | optional | Don't use impersonation | boolean | |
**is_public_folder** | optional | Mailbox folder is a public folder | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.dont_impersonate | boolean | | True False |
action_result.parameter.email | string | `email` | test@sample.com |
action_result.parameter.folder | string | `mail folder` `mail folder path` | Inbox |
action_result.parameter.id | string | `exchange email id` | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= |
action_result.parameter.impersonate_email | string | `email` | test@sample.com |
action_result.parameter.is_public_folder | boolean | | True False |
action_result.data.\*.new_email_id | string | `exchange email id` | |
action_result.summary | string | | |
action_result.message | string | | Email copied |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.ph | ph | | |

## action: 'move email'

Move an email to a folder

Type: **generic** <br>
Read only: **False**

The action supports moving an email to a folder that is nested within another.<br>To move to such a folder, specify the complete path using the <b>'/'</b> (forward slash) as the separator.<br>For example, to move email to a folder named <i>phishing</i> which is nested within <i>Inbox</i>, set the value as <b>Inbox/phishing</b>.<br>The action requires the exchange email ID as input. Many times this value is not easily available, since not many email clients display it. However every email header has a value called <b>Message-ID</b> assigned to it. It's usually something like \<tS10Ncty2SyeJsjdNMsxV+dguQ+jd7RwiFgmZsLN@contoso.com>. Use this <b>Internet Message ID</b> as input to the <b>run query</b> action to get the <b>exchange email ID</b> of an email.<br>The action will return the ID of the newly copied email in the data path <b>action_result.data.\*.new_email_id</b>, however this value is not available for cross-mailbox or mailbox to public folder <b>move email</b> actions (please see the documentation of the <a href="https://msdn.microsoft.com/en-us/library/office/aa565012(v=exchg.150).aspx">MoveItem operation on MSDN</a>). However in such scenarios, do a <b>run query</b> on the new mailbox plus folder with a specific parameter like <b>Internet Message ID</b> to get the <b>Exchange email ID</b>.<br><br><b>Impersonation</b><p>Impersonation plays a big role in the <b>move email</b> action, for reasons explained in this section, <b>move email</b> is the only action that overrides the asset config parameter <b>use_impersonation</b>. By default, the action will <i>impersonate</i> the user specified in the <b>email</b> parameter, if impersonation is enabled (by setting the <b>dont_impersonate</b> action parameter to False or Unchecked).<br>However depending on the server configuration, this action might fail with an <i>Access Denied</i> error. If an email is being copied from one folder to another in the same mailbox, the action will succeed, however if the email is being copied from one mailbox's folder to a different mailbox, the impersonated user will require access to both the mailboxes. In this case the action might require to impersonate a user other than the one specified in the <b>email</b> parameter. In such a scenario use the <b>impersonate_email</b> to specify an alternate email to <i>impersonate</i>.<br>Set the <b>dont_impersonate</b> parameter to <b>True</b> to disable impersonation all together. This value will override the one configured on the asset. The default value of this param is <b>False</b>.</p>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to move | string | `exchange email id` |
**email** | required | Destination Mailbox (Email) | string | `email` |
**folder** | required | Destination Mail Folder Name/Path | string | `mail folder` `mail folder path` |
**impersonate_email** | optional | Impersonation Email | string | `email` |
**dont_impersonate** | optional | Don't use impersonation | boolean | |
**is_public_folder** | optional | Mailbox folder is a public folder | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.dont_impersonate | boolean | | True False |
action_result.parameter.email | string | `email` | test@sample.com |
action_result.parameter.folder | string | `mail folder` `mail folder path` | Inbox |
action_result.parameter.id | string | `exchange email id` | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= |
action_result.parameter.impersonate_email | string | `email` | test@sample.com |
action_result.parameter.is_public_folder | boolean | | True False |
action_result.data.\*.new_email_id | string | `exchange email id` | |
action_result.summary | string | | |
action_result.message | string | | Email moved |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.ph | ph | | |

## action: 'get email'

Get an email from the server

Type: **investigate** <br>
Read only: **True**

Every container that is created by the app has the following values:<ul><li>The container ID that is generated by the Splunk SOAR platform.</li><li>The Source ID that the app equates to the email ID on the server if known or the vault ID if asked to parse from the vault.</li><li>If the asset configuration parameter "Save raw email to container data dictionary" is checked, then the raw_email data in the container's data field is set to the RFC822 format of the email.</li></ul>This action parses email data and if specified creates containers and artifacts. The email data to parse is either extracted from the remote server if an email ID is specified, from a Splunk SOAR container, if the <b>container_id</b> is specified or from the vault item if the <b>vault_id</b> is specified.<br>If all three parameters are specified, the action will use the <b>container_id</b>.<br>The data paths differ depending on where the email data is parsed from.<br><br><p>If parsed from the server:<br><ul><li>The data path <b>action_result.data.\*.t_MimeContent.#text</b> contains the email in RFC822 format, but base64 encoded.</li><li>The data path <b>action_result.data.\*.t_Body.#text</b> contains the email body.</li><li>The widget for this action will render a text version of the email body if possible.</li><li>If impersonation is enabled on the asset, the <b>email</b> parameter is required, else <b>email</b> will be ignored.</li></ul></p><p>If parsed from the container or vault:<br><ul><li>The widget does not render the email body.</li><li>The email headers are listed in a table.</li></ul></p><p>If <b>ingest_email</b> is set to </b>True</b>:<br><ul><li>The ID of the container created or updated will be set in the <b>action_result.summary.container_id</b> data path.</li><li>The widget will display this ID as <b>Ingested Container ID</b>.</li></ul></p>Do note that any containers and artifacts created will use the label configured in the asset.<br>The action will fail if the vault item asked to parse and ingest is not an email item (.eml).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | optional | Message ID to get | string | `exchange email id` |
**email** | optional | Email of the mailbox owner (used during impersonation) | string | `email` |
**container_id** | optional | Container ID to get email data from | numeric | `phantom container id` |
**vault_id** | optional | Vault ID to get email from | string | `vault id` |
**ingest_email** | optional | Create containers and artifacts | boolean | |
**use_current_container** | optional | Create artifacts in the same container | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_id | numeric | `phantom container id` | 1 |
action_result.parameter.email | string | `email` | test@sample.com |
action_result.parameter.id | string | `exchange email id` | AAMkADMzMGJmYzM0LThjZjYtNDQzMC04ZjNhLWNkYzYwYmViZDU2ZABGAAAAAAAYish+ZMlDQ6wcIrPHA5WYBwAcmY5GSia4RK5DAQM4jsrZAAAAAAEMAAAcmY5GSia4RK5DAQM4jsrZAADYNGhYAAABEgAQAAwVWunyyNdLvvCK9O44tTk= |
action_result.parameter.ingest_email | boolean | | True False |
action_result.parameter.use_current_container | boolean | | True False |
action_result.parameter.vault_id | string | `vault id` | 85735b9d35c6eccf3ee80f45648b9f7df613703c |
action_result.data.\*.CC | string | | Test <test@sample.com> |
action_result.data.\*.Content-Language | string | | en-US |
action_result.data.\*.Content-Type | string | | |
action_result.data.\*.Date | string | | |
action_result.data.\*.Delivered-To | string | | |
action_result.data.\*.From | string | | |
action_result.data.\*.Importance | string | | |
action_result.data.\*.MIME-Version | string | | |
action_result.data.\*.Mail-Filter-Gateway | string | | |
action_result.data.\*.Message-ID | string | `internet message id` | |
action_result.data.\*.Received | string | | |
action_result.data.\*.Return-Path | string | | |
action_result.data.\*.Sender | string | | |
action_result.data.\*.Subject | string | | Test subject |
action_result.data.\*.Thread-Index | string | | |
action_result.data.\*.Thread-Topic | string | | |
action_result.data.\*.To | string | | |
action_result.data.\*.X-Account-Key | string | | |
action_result.data.\*.X-CTCH-RefID | string | | |
action_result.data.\*.X-MS-Exchange-Organization-RecordReviewCfmType | string | | |
action_result.data.\*.X-MS-Exchange-Organization-SCL | string | | |
action_result.data.\*.X-MS-Has-Attach | string | | yes |
action_result.data.\*.X-MS-TNEF-Correlator | string | | |
action_result.data.\*.X-Mail-Filter-Gateway-From | string | `email` | |
action_result.data.\*.X-Mail-Filter-Gateway-ID | string | | |
action_result.data.\*.X-Mail-Filter-Gateway-SpamDetectionEngine | string | | |
action_result.data.\*.X-Mail-Filter-Gateway-SpamScore | string | | |
action_result.data.\*.X-Mail-Filter-Gateway-To | string | `email` | |
action_result.data.\*.X-Mailer | string | | |
action_result.data.\*.X-MimeOLE | string | | |
action_result.data.\*.X-Mozilla-Keys | string | | |
action_result.data.\*.X-Priority | string | | |
action_result.data.\*.X-SOHU-Antispam-Bayes | string | | |
action_result.data.\*.X-SOHU-Antispam-Language | string | | |
action_result.data.\*.X-Spam-Status | string | | |
action_result.data.\*.X-UIDL | string | | |
action_result.data.\*.decodedBCC | string | | test_user <test_user@e2016.local> |
action_result.data.\*.decodedCC | string | | test_user <test_user@e2016.local> |
action_result.data.\*.decodedFrom | string | | test_user <test_user@e2016.local> |
action_result.data.\*.decodedSubject | string | | test subject |
action_result.data.\*.decodedTo | string | | test_user <test_user@e2016.local> |
action_result.data.\*.t_AdjacentMeetingCount | string | | 0 |
action_result.data.\*.t_AssociatedCalendarItemId.@ChangeKey | string | | DwAAABYAAAAcmY5GSia4RK5DAQM4jsrZAAF/yWMW |
action_result.data.\*.t_AssociatedCalendarItemId.@Id | string | | AAMkADMzMGJmYzM0LThjZjYtNDQzMC04ZjNhLWNkYzYwYmViZDU2ZABGAAAAAAAYish+ZMlDQ6wcIrPHA5WYBwAcmY5GSia4RK5DAQM4jsrZAAAAAAENAAAcmY5GSia4RK5DAQM4jsrZAAF/xerCAAA= |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_AttachmentId.@Id | string | | AAMkADMzMGJmYzM0LThjZjYtNDQzMC04ZjNhLWNkYzYwYmViZDU2ZABGAAAAAAAYish+ZMlDQ6wcIrPHA5WYBwAcmY5GSia4RK5DAQM4jsrZAAAAAAEMAAAcmY5GSia4RK5DAQM4jsrZAADYNGhXAAABEgAQAFAEZruSqddCnoHkoKpp2Fw= |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_ContentId | string | | |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_ContentType | string | | text/rtf |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_IsContactPhoto | string | | false |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_IsInline | string | | false |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_LastModifiedTime | string | | 2019-03-03T10:25:14 |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_Name | string | `user name` | test_filename |
action_result.data.\*.t_Attachments.t_FileAttachment.\*.t_Size | string | | 577 |
action_result.data.\*.t_Attachments.t_FileAttachment.t_AttachmentId.@Id | string | | AAMkADMzMGJmYzM0LThjZjYtNDQzMC04ZjNhLWNkYzYwYmViZDU2ZABGAAAAAAAYish+ZMlDQ6wcIrPHA5WYBwAcmY5GSia4RK5DAQM4jsrZAAAAAAEMAAAcmY5GSia4RK5DAQM4jsrZAADYNGhYAAABEgAQAAwVWunyyNdLvvCK9O44tTk= |
action_result.data.\*.t_Attachments.t_FileAttachment.t_ContentId | string | | |
action_result.data.\*.t_Attachments.t_FileAttachment.t_ContentType | string | | text/rtf |
action_result.data.\*.t_Attachments.t_FileAttachment.t_IsContactPhoto | string | | false |
action_result.data.\*.t_Attachments.t_FileAttachment.t_IsInline | string | | false |
action_result.data.\*.t_Attachments.t_FileAttachment.t_LastModifiedTime | string | | 2019-03-03T11:20:20 |
action_result.data.\*.t_Attachments.t_FileAttachment.t_Name | string | `user name` | test_filename |
action_result.data.\*.t_Attachments.t_FileAttachment.t_Size | string | | 686 |
action_result.data.\*.t_Attachments.t_ItemAttachment.\*.t_AttachmentId.@Id | string | | AAMkADMzMGJmYzM0LThjZjYtNDQzMC04ZjNhLWNkYzYwYmViZDU2ZABGAAAAAAAYish+ZMlDQ6wcIrPHA5WYBwAcmY5GSia4RK5DAQM4jsrZAAF/xJHpAAAcmY5GSia4RK5DAQM4jsrZAAGp8gueAAABEgAQANfKOfHITtpGoin5+WHGFes= |
action_result.data.\*.t_Attachments.t_ItemAttachment.\*.t_IsInline | string | | false |
action_result.data.\*.t_Attachments.t_ItemAttachment.\*.t_LastModifiedTime | string | | 2021-12-06T10:16:41 |
action_result.data.\*.t_Attachments.t_ItemAttachment.\*.t_Name | string | | Project discussion |
action_result.data.\*.t_Attachments.t_ItemAttachment.\*.t_Size | string | | 10944 |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_AttachmentId.@Id | string | | AAMkADdjMTIzMWQ3LTZjNWMtNDY1YS05NWQxLTNjYWEyZmQ3YzM1NABGAAAAAAAJSwjkHb8oQah/TEDLmhZUBwAkoMp0B6/1Tp1ZFVDIcuRVAAAAQCMBAAAkoMp0B6/1Tp1ZFVDIcuRVAAABk685AAABBgAEAAAAAAA= |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_ContentId | string | | 055B64DA80B87347B158187A516CB65A@sample.com |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_ContentType | string | | message/rfc822 |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_IsInline | string | | false |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_LastModifiedTime | string | | 2020-06-03T12:33:51 |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_Name | string | | |
action_result.data.\*.t_Attachments.t_ItemAttachment.t_Size | string | | 923 |
action_result.data.\*.t_Body.#text | string | | Test body. |
action_result.data.\*.t_Body.@BodyType | string | | Text |
action_result.data.\*.t_Body.@IsTruncated | string | | false |
action_result.data.\*.t_Categories.t_String | string | | Processing |
action_result.data.\*.t_CcRecipients.t_Mailbox.t_EmailAddress | string | | user1@e2016.local |
action_result.data.\*.t_CcRecipients.t_Mailbox.t_MailboxType | string | | Mailbox |
action_result.data.\*.t_CcRecipients.t_Mailbox.t_Name | string | | user1 |
action_result.data.\*.t_CcRecipients.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_ConflictingMeetingCount | string | | 0 |
action_result.data.\*.t_DateTimeCreated | string | | 2017-10-03T21:31:05Z |
action_result.data.\*.t_DateTimeReceived | string | | 2017-10-03T21:31:05Z |
action_result.data.\*.t_DateTimeSent | string | | 2017-10-03T21:31:05Z |
action_result.data.\*.t_End | string | | 2021-11-27T16:30:00Z |
action_result.data.\*.t_ExtendedProperty.\*.t_ExtendedFieldURI.@PropertyTag | string | | 0x7d |
action_result.data.\*.t_ExtendedProperty.\*.t_ExtendedFieldURI.@PropertyType | string | | String |
action_result.data.\*.t_ExtendedProperty.\*.t_Value | string | | |
action_result.data.\*.t_ExtendedProperty.t_ExtendedFieldURI.@PropertyTag | string | | |
action_result.data.\*.t_ExtendedProperty.t_ExtendedFieldURI.@PropertyType | string | | String |
action_result.data.\*.t_ExtendedProperty.t_Value | string | | |
action_result.data.\*.t_From.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_From.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_From.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_From.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_HasAttachments | string | | |
action_result.data.\*.t_HasBeenProcessed | string | | true |
action_result.data.\*.t_IntendedFreeBusyStatus | string | | Busy |
action_result.data.\*.t_InternetMessageId | string | `internet message id` | |
action_result.data.\*.t_IsAssociated | string | | |
action_result.data.\*.t_IsDelegated | string | | false |
action_result.data.\*.t_IsDeliveryReceiptRequested | string | | false |
action_result.data.\*.t_IsOutOfDate | string | | true |
action_result.data.\*.t_IsRead | string | | |
action_result.data.\*.t_IsReadReceiptRequested | string | | |
action_result.data.\*.t_ItemId.@ChangeKey | string | | |
action_result.data.\*.t_ItemId.@Id | string | | |
action_result.data.\*.t_LastModifiedTime | string | | 2017-10-31T01:09:20Z |
action_result.data.\*.t_Location | string | | |
action_result.data.\*.t_MeetingRequestType | string | | NewMeetingRequest |
action_result.data.\*.t_MimeContent.#text | string | | |
action_result.data.\*.t_MimeContent.@CharacterSet | string | | UTF-8 |
action_result.data.\*.t_Organizer.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_Organizer.t_Mailbox.t_MailboxType | string | | Mailbox |
action_result.data.\*.t_Organizer.t_Mailbox.t_Name | string | `user name` | user |
action_result.data.\*.t_Organizer.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_MailboxType | string | | Mailbox |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_Name | string | `user name` | user |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_ResponseType | string | | Unknown |
action_result.data.\*.t_ResponseObjects.t_AcceptItem | string | | |
action_result.data.\*.t_ResponseObjects.t_DeclineItem | string | | |
action_result.data.\*.t_ResponseObjects.t_ForwardItem | string | | |
action_result.data.\*.t_ResponseObjects.t_ProposeNewTime | string | | |
action_result.data.\*.t_ResponseObjects.t_ReplyAllToItem | string | | |
action_result.data.\*.t_ResponseObjects.t_ReplyToItem | string | | |
action_result.data.\*.t_ResponseObjects.t_TentativelyAcceptItem | string | | |
action_result.data.\*.t_ResponseType | string | | NoResponseReceived |
action_result.data.\*.t_Sender.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_Sender.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_Sender.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_Sender.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_Sensitivity | string | | |
action_result.data.\*.t_Size | string | | |
action_result.data.\*.t_Start | string | | 2021-11-27T16:00:00Z |
action_result.data.\*.t_Subject | string | | |
action_result.data.\*.t_TextBody.#text | string | | This is a test email |
action_result.data.\*.t_TextBody.@BodyType | string | | Text |
action_result.data.\*.t_TextBody.@IsTruncated | string | | false |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_MailboxType | string | | |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_Name | string | `user name` | |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_RoutingType | string | | SMTP |
action_result.summary.container_id | numeric | `phantom container id` | |
action_result.summary.create_time | string | | |
action_result.summary.email_id | numeric | `exchange email id` | |
action_result.summary.sent_time | string | | |
action_result.summary.subject | string | | |
action_result.message | string | | Subject: Test subject, Create time: 2018-09-04T14:12:39Z, Sent time: 2018-09-04T14:13:48Z |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list addresses'

Get the email addresses that make up a Distribution List

Type: **investigate** <br>
Read only: **True**

The <b>group</b> parameter supports, as input, the email (for e.g. dleng@corp.contoso.com) or the name (for e.g. dleng) of the distribution list.<br><br>The <b>recursive</b> parameter will cause the action to recursively search for distribution lists inside of the initial distribution lists and expand those.<br>Each discovered distribution list will be submitted as a separate set of results, causing multiple sets of action results to be created.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group** | required | Distribution List to expand | string | `email` `exchange distribution list` `user name` |
**recursive** | optional | Expand all sub distribution lists | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.group | string | `email` `exchange distribution list` `user name` | Group |
action_result.parameter.recursive | boolean | | True False |
action_result.data.\*.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_MailboxType | string | | |
action_result.data.\*.t_Name | string | `user name` | test |
action_result.data.\*.t_RoutingType | string | | SMTP |
action_result.summary.total_entries | numeric | | 3 |
action_result.message | string | | Total entries: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup email'

Resolve an Alias name or email address, into mailboxes

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | required | Name to resolve | string | `exchange alias` `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.email | string | `exchange alias` `email` | test@sample.com |
action_result.data.\*.t_Contact.t_AssistantName | string | | |
action_result.data.\*.t_Contact.t_CompanyName | string | | |
action_result.data.\*.t_Contact.t_ContactSource | string | | |
action_result.data.\*.t_Contact.t_Culture | string | | en-GB |
action_result.data.\*.t_Contact.t_Department | string | | |
action_result.data.\*.t_Contact.t_DisplayName | string | | |
action_result.data.\*.t_Contact.t_EmailAddresses.\*.#text | string | | RnJvbTogUGhhbnRvbSBVc2VyIDxwaGFudG9t... |
action_result.data.\*.t_Contact.t_EmailAddresses.\*.@Key | string | | |
action_result.data.\*.t_Contact.t_GivenName | string | | |
action_result.data.\*.t_Contact.t_Initials | string | | |
action_result.data.\*.t_Contact.t_JobTitle | string | | |
action_result.data.\*.t_Contact.t_Manager | string | | |
action_result.data.\*.t_Contact.t_OfficeLocation | string | | |
action_result.data.\*.t_Contact.t_PhoneNumbers.t_Entry.\*.#text | string | | |
action_result.data.\*.t_Contact.t_PhoneNumbers.t_Entry.\*.@Key | string | | |
action_result.data.\*.t_Contact.t_PhysicalAddresses.t_Entry.@Key | string | | |
action_result.data.\*.t_Contact.t_PhysicalAddresses.t_Entry.t_City | string | | |
action_result.data.\*.t_Contact.t_PhysicalAddresses.t_Entry.t_CountryOrRegion | string | | |
action_result.data.\*.t_Contact.t_PhysicalAddresses.t_Entry.t_PostalCode | string | | |
action_result.data.\*.t_Contact.t_PhysicalAddresses.t_Entry.t_State | string | | |
action_result.data.\*.t_Contact.t_PhysicalAddresses.t_Entry.t_Street | string | | |
action_result.data.\*.t_Contact.t_Surname | string | | |
action_result.data.\*.t_Mailbox.t_EmailAddress | string | | test@sample.com |
action_result.data.\*.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.summary.total_entries | numeric | | 1 |
action_result.message | string | | Total entries: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update email'

Update an email on the server

Type: **generic** <br>
Read only: **False**

Currently this action only updates the category and subject of an email. To set multiple categories, please pass a comma separated list to the <b>category</b> parameter.<br>NOTE: If the user tries to update the categories, then the existing categories of the email will be replaced with the new categories provided as input.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to update | string | `exchange email id` |
**email** | optional | Email of the mailbox owner (used during impersonation) | string | `email` |
**subject** | optional | Subject to set | string | |
**category** | optional | Categories to set | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.category | string | | Yellow, Blue, Purple, red |
action_result.parameter.email | string | `email` | test@sample.com |
action_result.parameter.id | string | `exchange email id` | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= |
action_result.parameter.subject | string | | Both value are modified |
action_result.data.\*.t_AdjacentMeetingCount | string | | 0 |
action_result.data.\*.t_AssociatedCalendarItemId.@ChangeKey | string | | DwAAABYAAAAcmY5GSia4RK5DAQM4jsrZAAGp9bBK |
action_result.data.\*.t_AssociatedCalendarItemId.@Id | string | | AAMkADMzMGJmYzM0LThjZjYtNDQzMC04ZjNhLWNkYzYwYmViZDU2ZABGAAAAAAAYish+ZMlDQ6wcIrPHA5WYBwAcmY5GSia4RK5DAQM4jsrZAAAAAAENAAAcmY5GSia4RK5DAQM4jsrZAAGp8gO+AAA= |
action_result.data.\*.t_Attachments.t_FileAttachment.t_AttachmentId.@Id | string | | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAABEgAQAHAXDtZM8ItNnDTtvcd6IAo= |
action_result.data.\*.t_Attachments.t_FileAttachment.t_ContentId | string | `email` | 7518226202D21C4397EE1CB1E2E540C7@sample.com |
action_result.data.\*.t_Attachments.t_FileAttachment.t_ContentType | string | | application/octet-stream |
action_result.data.\*.t_Attachments.t_FileAttachment.t_IsContactPhoto | string | | false |
action_result.data.\*.t_Attachments.t_FileAttachment.t_IsInline | string | | false |
action_result.data.\*.t_Attachments.t_FileAttachment.t_LastModifiedTime | string | | 2017-10-03T21:31:05 |
action_result.data.\*.t_Attachments.t_FileAttachment.t_Name | string | `user name` | test.msg |
action_result.data.\*.t_Attachments.t_FileAttachment.t_Size | string | | 55360 |
action_result.data.\*.t_Body.#text | string | | Attached .msg file. Hello |
action_result.data.\*.t_Body.@BodyType | string | | Text |
action_result.data.\*.t_Body.@IsTruncated | string | | false |
action_result.data.\*.t_Categories | string | | red |
action_result.data.\*.t_ConflictingMeetingCount | string | | 1 |
action_result.data.\*.t_DateTimeCreated | string | | 2017-10-05T20:19:58Z |
action_result.data.\*.t_DateTimeReceived | string | | 2017-10-03T21:31:05Z |
action_result.data.\*.t_DateTimeSent | string | | 2017-10-03T21:31:20Z |
action_result.data.\*.t_End | string | | 2021-12-02T13:30:00Z |
action_result.data.\*.t_ExtendedProperty.t_ExtendedFieldURI.@PropertyTag | string | | |
action_result.data.\*.t_ExtendedProperty.t_ExtendedFieldURI.@PropertyType | string | | String |
action_result.data.\*.t_ExtendedProperty.t_Value | string | | |
action_result.data.\*.t_From.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_From.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_From.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_From.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_HasAttachments | string | | true |
action_result.data.\*.t_HasBeenProcessed | string | | true |
action_result.data.\*.t_IntendedFreeBusyStatus | string | | Busy |
action_result.data.\*.t_InternetMessageId | string | | <81c761fe-caa8-f924-f65d-079382c1ad0b@sample.com> |
action_result.data.\*.t_IsAssociated | string | | false |
action_result.data.\*.t_IsDelegated | string | | false |
action_result.data.\*.t_IsDeliveryReceiptRequested | string | | false |
action_result.data.\*.t_IsOutOfDate | string | | false |
action_result.data.\*.t_IsRead | string | | true |
action_result.data.\*.t_IsReadReceiptRequested | string | | false |
action_result.data.\*.t_ItemId.@ChangeKey | string | | CQAAABYAAACQhMsoV7EYSJF42ChR9SCxAAAAj9UU |
action_result.data.\*.t_ItemId.@Id | string | | AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= |
action_result.data.\*.t_LastModifiedTime | string | | 2017-10-31T01:09:20Z |
action_result.data.\*.t_Location | string | | |
action_result.data.\*.t_MeetingRequestType | string | | NewMeetingRequest |
action_result.data.\*.t_MimeContent.#text | string | | RnJvbTogUGhhbnRvbSBVc2VyIDxwaGFudG9t... |
action_result.data.\*.t_MimeContent.@CharacterSet | string | | UTF-8 |
action_result.data.\*.t_Organizer.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_Organizer.t_Mailbox.t_MailboxType | string | | Mailbox |
action_result.data.\*.t_Organizer.t_Mailbox.t_Name | string | `user name` | user |
action_result.data.\*.t_Organizer.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_MailboxType | string | | Mailbox |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_Name | string | `user name` | user |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_RequiredAttendees.t_Attendee.\*.t_ResponseType | string | | Unknown |
action_result.data.\*.t_ResponseObjects.t_AcceptItem | string | | |
action_result.data.\*.t_ResponseObjects.t_DeclineItem | string | | |
action_result.data.\*.t_ResponseObjects.t_ForwardItem | string | | |
action_result.data.\*.t_ResponseObjects.t_ProposeNewTime | string | | |
action_result.data.\*.t_ResponseObjects.t_ReplyAllToItem | string | | |
action_result.data.\*.t_ResponseObjects.t_ReplyToItem | string | | |
action_result.data.\*.t_ResponseObjects.t_TentativelyAcceptItem | string | | |
action_result.data.\*.t_ResponseType | string | | NoResponseReceived |
action_result.data.\*.t_Sender.t_Mailbox.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_Sender.t_Mailbox.t_MailboxType | string | | OneOff |
action_result.data.\*.t_Sender.t_Mailbox.t_Name | string | `user name` | Test |
action_result.data.\*.t_Sender.t_Mailbox.t_RoutingType | string | | SMTP |
action_result.data.\*.t_Sensitivity | string | | Normal |
action_result.data.\*.t_Size | string | | 56353 |
action_result.data.\*.t_Start | string | | 2021-12-02T12:30:00Z |
action_result.data.\*.t_Subject | string | | Both value are modified |
action_result.data.\*.t_TextBody.#text | string | | Test body. |
action_result.data.\*.t_TextBody.@BodyType | string | | Text |
action_result.data.\*.t_TextBody.@IsTruncated | string | | false |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_EmailAddress | string | `email` | test@sample.com |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_MailboxType | string | | Mailbox |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_Name | string | `user name` | Test User |
action_result.data.\*.t_ToRecipients.t_Mailbox.\*.t_RoutingType | string | | SMTP |
action_result.summary.create_time | string | | 2017-10-05T20:19:58Z |
action_result.summary.sent_time | string | | 2017-10-03T21:31:20Z |
action_result.summary.subject | string | | Both value are modified |
action_result.message | string | | Create time: 2017-10-05T20:19:58Z Subject: Both value are modified Sent time: 2017-10-03T21:31:20Z |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Ingest emails from the server into Splunk SOAR

Type: **ingest** <br>
Read only: **True**

Please see sections <a href="#poll_now">POLL NOW</a> and <a href="#scheduled_polling">Scheduled Polling</a> for more info on how this action is implemented by the app.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Parameter Ignored in this app | numeric | |
**end_time** | optional | Parameter Ignored in this app | numeric | |
**container_id** | optional | Parameter Ignored in this app | numeric | |
**container_count** | required | Maximum number of emails to ingest | numeric | |
**artifact_count** | optional | Parameter Ignored in this app | numeric | |

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
