rule Anti_Forensics_Windows_Enumeration_Check
{
  meta:
		author			= "Phillip Kittelson"
		description		= "Signature checks for an anti-forensics method of enumperating program windows and checking the windows title property for a common list of debunning and forensic tools."
		date			= "2023-08-12"
		reference		= "https://www.virustotal.com/gui/file/c8a5262e89751f231060a6740447062e34c5393a17f67d0c4eb52c7f911f3bd2/content/strings"
		vrsion			= "1.1"
		
  strings:
		
		$GetWindowText1="GetWindowTextA" nocase wide ascii
		$GetWindowText2={47 65 74 57 69 6E 64 6F 77 54 65 78 74 41}
		
		$TermProcess1="TerminateProcess"
		$TermProcess2={54 65 72 6D 69 6E 61 74 65 50 72 6F 63 65 73 73}
		
		$WindowTitle1="proxifier" nocase wide ascii
		$WindowTitle2="graywolf" nocase wide ascii
		$WindowTitle3="extremedumper" nocase wide ascii
		$WindowTitle4="zed" nocase wide ascii
		$WindowTitle5="exeinfope" nocase wide ascii
		$WindowTitle6="dnspy" nocase wide ascii
		$WindowTitle7="titanHide" nocase wide ascii
		$WindowTitle8="ilspy" nocase wide ascii
		$WindowTitle9="titanhide" nocase wide ascii
		$WindowTitle10="x32dbg" nocase wide ascii
		$WindowTitle11="codecracker" nocase wide ascii
		$WindowTitle12="simpleassembly" nocase wide ascii
		$WindowTitle13="pc-ret" nocase wide ascii
		$WindowTitle14="http cdebugger" nocase wide ascii
		$WindowTitle15="Centos" nocase wide ascii
		$WindowTitle16="process monitor" nocase wide ascii
		$WindowTitle17="debug" nocase wide ascii
		$WindowTitle18="ILSpy" nocase wide ascii
		$WindowTitle19="reverse" nocase wide ascii
		$WindowTitle20="simpleassemblyexplorer" nocase wide ascii
		$WindowTitle21="process" nocase wide ascii
		$WindowTitle22="de4dotmodded" nocase wide ascii
		$WindowTitle23="dojandqwklndoqwd-x86" nocase wide ascii
		$WindowTitle24="sharpod" nocase wide ascii
		$WindowTitle25="folderchangesview" nocase wide ascii
		$WindowTitle26="fiddler" nocase wide ascii
		$WindowTitle27="die" nocase wide ascii
		$WindowTitle28="pizza" nocase wide ascii
		$WindowTitle29="crack" nocase wide ascii
		$WindowTitle30="strongod" nocase wide ascii
		$WindowTitle31="ida-" nocase wide ascii
		$WindowTitle32="brute" nocase wide ascii
		$WindowTitle33="dump" nocase wide ascii
		$WindowTitle34="StringDecryptor" nocase wide ascii
		$WindowTitle35="wireshark" nocase wide ascii
		$WindowTitle36="debugger" nocase wide ascii
		$WindowTitle37="httpdebugger" nocase wide ascii
		$WindowTitle38="gdb" nocase wide ascii
		$WindowTitle39="kdb" nocase wide ascii
		$WindowTitle40="x64_dbg" nocase wide ascii
		$WindowTitle41="windbg" nocase wide ascii
		$WindowTitle42="x64netdumper" nocase wide ascii
		$WindowTitle43="petools" nocase wide ascii
		$WindowTitle44="megadumper" nocase wide ascii
		$WindowTitle45="reversal" nocase wide ascii
		$WindowTitle46="ksdumper 1.1-by equifox" nocase wide ascii
		$WindowTitle47="dbgclr" nocase wide ascii
		$WindowTitle48="HxD" nocase wide ascii
		$WindowTitle49="monitor" nocase wide ascii
		$WindowTitle50="peek" nocase wide ascii
		$WindowTitle51="ollydbg" nocase wide ascii
		$WindowTitle52="ksdumper" nocase wide ascii
		$WindowTitle53="http" nocase wide ascii
		$WindowTitle54="wpe pro" nocase wide ascii
		$WindowTitle55="dbg" nocase wide ascii
		$WindowTitle56="httpanalyzer" nocase wide ascii
		$WindowTitle57="httpdebug" nocase wide ascii
		$WindowTitle58="PhantOm" nocase wide ascii
		$WindowTitle59="kgdb" nocase wide ascii
		$WindowTitle60="james" nocase wide ascii
		$WindowTitle61="x32_dbg" nocase wide ascii
		$WindowTitle62="proxy" nocase wide ascii
		$WindowTitle63="phantom" nocase wide ascii
		$WindowTitle64="mdbg" nocase wide ascii
		$WindowTitle65="WPE PRO" nocase wide ascii
		$WindowTitle66="system explorer" nocase wide ascii
		$WindowTitle67="de4dot" nocase wide ascii
		$WindowTitle68="x64dbg" nocase wide ascii
		$WindowTitle69="X64NetDumper" nocase wide ascii
		$WindowTitle70="protection_id" nocase wide ascii
		$WindowTitle71="charles" nocase wide ascii
		$WindowTitle72="systemexplorer" nocase wide ascii
		$WindowTitle73="pepper" nocase wide ascii
		$WindowTitle74="hxd" nocase wide ascii
		$WindowTitle75="procmon64" nocase wide ascii
		$WindowTitle76="MegaDumper" nocase wide ascii
		$WindowTitle77="ghidra" nocase wide ascii
		$WindowTitle78="xd" nocase wide ascii
		$WindowTitle79="0harmony" nocase wide ascii
		$WindowTitle80="dojandqwklndoqwd" nocase wide ascii
		$WindowTitle81="hacker" nocase wide ascii
		$WindowTitle82="process hacker" nocase wide ascii
		$WindowTitle83="SAE" nocase wide ascii
		$WindowTitle84="mdb" nocase wide ascii
		$WindowTitle85="checker" nocase wide ascii
		$WindowTitle86="harmony" nocase wide ascii
		$WindowTitle87="Protection_ID" nocase wide ascii
		$WindowTitle88="PETools" nocase wide ascii
		$WindowTitle89="scyllaHide" nocase wide ascii
		$WindowTitle90="x96dbg" nocase wide ascii
		$WindowTitle91="systemexplorerservice" nocase wide ascii
		$WindowTitle92="folder" nocase wide ascii
		$WindowTitle93="mitmproxy" nocase wide ascii
		$WindowTitle94="dbx" nocase wide ascii
		$WindowTitle95="sniffer" nocase wide ascii
		$WindowTitle96="http toolkit" nocase wide ascii
		$WindowTitle97="process hacker 2" nocase wide ascii
		$WindowTitle98="scyllahide" nocase wide ascii
		
	condition:
		
		($GetWindowText1 or $GetWindowText2) or ($TermProcess1 or $TermProcess2) and any of ($WindowTitle*)		
}