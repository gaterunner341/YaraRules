rule Business_Email_Uploaded_to_VirusTotal
{
  meta:
		author			= "Phillip Kittelson"
		description		= "Search for your business email addresses invovled in breaches uploaded to VirusTotal"
		date			= "2023-08-25"
		version			= "1.1"
		
  strings:
		
		$emailString1="@businessdomain.com" nocase wide ascii
		$emailString2="@otherbusinessdomain.com" nocase wide ascii
		$PDF="%PDF" //Excludes PDF files which can contain lots of embeded email addresses, remove if PDF is desired.
		
	condition:
		
		any of ($emailString*) and not $PDF at 0
}