# YaraRules
 
A collection my Yara rules.


- **Anti_Forensics_Windows_Enumeration_Check**: A YARA rule to find files which attempt to enumerate Microsoft Windows program window names with common debugging or forensic tools.
- **Business_Email_Uploaded_to_VirusTotal**: A YARA rule to find your buiness email domains in password dumps uploaded to VirusTotal. Excludes PDF, which could contain embeded emails in reports. Remove this option is desired.

[!NOTE]
When available, each YARA file (.yar) will be accompained by a sample file which would be detected with that definition.