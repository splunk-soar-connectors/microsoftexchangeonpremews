**Unreleased**
* Escaped some special characters from the file name [PAPP-26522]
* Removed new line characters from the email subject [PAPP-27016]
* Improved extract IOCs functionality
* Added 'decodedBCC' field in the email artifact
* Updated 'get email' action message with ingested container id
* Fixed 'get email' ingested artifact fields in case of updated email
* Removed the 'unify_cef_fields' asset configuration parameter 
* Added support for updating the container name if the email has been updated 
* Fixed the 'decoded fields' in email artifact