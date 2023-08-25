rule Business_Email_Uploaded_to_VirusTotal
{
  meta:
		author			= "Phillip Kittelson"
		description		= "Search for your business email addresses invovled in breaches uploaded to VirusTotal"
		date			= "2023-08-25"
		version			= "1.0"
		
  strings:
		
		$emailString1="@businessdomain.com" nocase wide ascii
		$emailString2="@otherbusinessdomain.com" nocase wide ascii
		
	condition:
		
		any of ($emailString*)	
}