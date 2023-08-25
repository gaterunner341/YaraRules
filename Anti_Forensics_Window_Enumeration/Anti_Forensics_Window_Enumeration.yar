rule Anti_Forensics_Windows_Enumeration_Check
{
  meta:
		author			= "Phillip Kittelson"
		description		= "Signature checks for an anti-forensics method of enumerating program windows and checking the windows title property for a common list of debugging and forensic tools."
		date			= "2023-08-12"
		reference		= "https://www.virustotal.com/gui/file/c8a5262e89751f231060a6740447062e34c5393a17f67d0c4eb52c7f911f3bd2/content/strings"
		version			= "1.2"
		
  strings:
		
		$GetWindowText="GetWindowTextA" nocase wide
		$TermProcess="TerminateProcess" nocase wide
	
		$WindowTitle1="proxifier" nocase wide
		$WindowTitle2="graywolf" nocase wide
		$WindowTitle3="extremedumper" nocase wide
		$WindowTitle4="zed" nocase wide
		$WindowTitle5="exeinfope" nocase wide
		$WindowTitle6="dnspy" nocase wide
		$WindowTitle7="titanHide" nocase wide
		$WindowTitle8="ilspy" nocase wide
		$WindowTitle9="titanhide" nocase wide
		$WindowTitle10="x32dbg" nocase wide
		$WindowTitle11="codecracker" nocase wide
		$WindowTitle12="simpleassembly" nocase wide
		$WindowTitle13="pc-ret" nocase wide
		$WindowTitle14="http cdebugger" nocase wide
		$WindowTitle15="Centos" nocase wide
		$WindowTitle16="process monitor" nocase wide
		$WindowTitle17="debug" nocase wide
		$WindowTitle18="ILSpy" nocase wide
		$WindowTitle19="reverse" nocase wide
		$WindowTitle20="simpleassemblyexplorer" nocase wide
		$WindowTitle21="process" nocase wide
		$WindowTitle22="de4dotmodded" nocase wide
		$WindowTitle23="dojandqwklndoqwd-x86" nocase wide
		$WindowTitle24="sharpod" nocase wide
		$WindowTitle25="folderchangesview" nocase wide
		$WindowTitle26="fiddler" nocase wide
		$WindowTitle27="die" nocase wide
		$WindowTitle28="pizza" nocase wide
		$WindowTitle29="crack" nocase wide
		$WindowTitle30="strongod" nocase wide
		$WindowTitle31="ida-" nocase wide
		$WindowTitle32="brute" nocase wide
		$WindowTitle33="dump" nocase wide
		$WindowTitle34="StringDecryptor" nocase wide
		$WindowTitle35="wireshark" nocase wide
		$WindowTitle36="debugger" nocase wide
		$WindowTitle37="httpdebugger" nocase wide
		$WindowTitle38="gdb" nocase wide
		$WindowTitle39="kdb" nocase wide
		$WindowTitle40="x64_dbg" nocase wide
		$WindowTitle41="windbg" nocase wide
		$WindowTitle42="x64netdumper" nocase wide
		$WindowTitle43="petools" nocase wide
		$WindowTitle44="megadumper" nocase wide
		$WindowTitle45="reversal" nocase wide
		$WindowTitle46="ksdumper 1.1-by equifox" nocase wide
		$WindowTitle47="dbgclr" nocase wide
		$WindowTitle48="HxD" nocase wide
		$WindowTitle49="monitor" nocase wide
		$WindowTitle50="peek" nocase wide
		$WindowTitle51="ollydbg" nocase wide
		$WindowTitle52="ksdumper" nocase wide
		$WindowTitle53="http" nocase wide
		$WindowTitle54="wpe pro" nocase wide
		$WindowTitle55="dbg" nocase wide
		$WindowTitle56="httpanalyzer" nocase wide
		$WindowTitle57="httpdebug" nocase wide
		$WindowTitle58="PhantOm" nocase wide
		$WindowTitle59="kgdb" nocase wide
		$WindowTitle60="james" nocase wide
		$WindowTitle61="x32_dbg" nocase wide
		$WindowTitle62="proxy" nocase wide
		$WindowTitle63="phantom" nocase wide
		$WindowTitle64="mdbg" nocase wide
		$WindowTitle65="WPE PRO" nocase wide
		$WindowTitle66="system explorer" nocase wide
		$WindowTitle67="de4dot" nocase wide
		$WindowTitle68="x64dbg" nocase wide
		$WindowTitle69="X64NetDumper" nocase wide
		$WindowTitle70="protection_id" nocase wide
		$WindowTitle71="charles" nocase wide
		$WindowTitle72="systemexplorer" nocase wide
		$WindowTitle73="pepper" nocase wide
		$WindowTitle74="hxd" nocase wide
		$WindowTitle75="procmon64" nocase wide
		$WindowTitle76="MegaDumper" nocase wide
		$WindowTitle77="ghidra" nocase wide
		$WindowTitle78="xd" nocase wide
		$WindowTitle79="0harmony" nocase wide
		$WindowTitle80="dojandqwklndoqwd" nocase wide
		$WindowTitle81="hacker" nocase wide
		$WindowTitle82="process hacker" nocase wide
		$WindowTitle83="SAE" nocase wide
		$WindowTitle84="mdb" nocase wide
		$WindowTitle85="checker" nocase wide
		$WindowTitle86="harmony" nocase wide
		$WindowTitle87="Protection_ID" nocase wide
		$WindowTitle88="PETools" nocase wide
		$WindowTitle89="scyllaHide" nocase wide
		$WindowTitle90="x96dbg" nocase wide
		$WindowTitle91="systemexplorerservice" nocase wide
		$WindowTitle92="folder" nocase wide
		$WindowTitle93="mitmproxy" nocase wide
		$WindowTitle94="dbx" nocase wide
		$WindowTitle95="sniffer" nocase wide
		$WindowTitle96="http toolkit" nocase wide
		$WindowTitle97="process hacker 2" nocase wide
		$WindowTitle98="scyllahide" nocase wide
		
	condition:
		
		($GetWindowText) or ($TermProcess) and any of ($WindowTitle*)		
}