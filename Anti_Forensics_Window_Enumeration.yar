rule Anti_Forensics_Windows_Enumeration_Check
{
  meta:
		author			= "Phillip Kittelson"
		description		= "Signature checks for enumperation of browser windows as an anti-forensics method"
		date			= "2023-08-12"
		reference		= ""
		
  strings:
		
		$a1="GetWindowTextA" nocase wide ascii
		$a2={47 65 74 57 69 6E 64 6F 77 54 65 78 74 41}
		
		$b1="TerminateProcess"
		$b2={54 65 72 6D 69 6E 61 74 65 50 72 6F 63 65 73 73}
		
		$c1="proxifier" nocase wide ascii
		$c2="graywolf" nocase wide ascii
		$c3="extremedumper" nocase wide ascii
		$c4="zed" nocase wide ascii
		$c5="exeinfope" nocase wide ascii
		$c6="dnspy" nocase wide ascii
		$c7="titanHide" nocase wide ascii
		$c8="ilspy" nocase wide ascii
		$c9="titanhide" nocase wide ascii
		$c10="x32dbg" nocase wide ascii
		$c11="codecracker" nocase wide ascii
		$c12="simpleassembly" nocase wide ascii
		$c13="pc-ret" nocase wide ascii
		$c14="http cdebugger" nocase wide ascii
		$c15="Centos" nocase wide ascii
		$c16="process monitor" nocase wide ascii
		$c17="debug" nocase wide ascii
		$c18="ILSpy" nocase wide ascii
		$c19="reverse" nocase wide ascii
		$c20="simpleassemblyexplorer" nocase wide ascii
		$c21="process" nocase wide ascii
		$c22="de4dotmodded" nocase wide ascii
		$c23="dojandqwklndoqwd-x86" nocase wide ascii
		$c24="sharpod" nocase wide ascii
		$c25="folderchangesview" nocase wide ascii
		$c26="fiddler" nocase wide ascii
		$c27="die" nocase wide ascii
		$c28="pizza" nocase wide ascii
		$c29="crack" nocase wide ascii
		$c30="strongod" nocase wide ascii
		$c31="ida-" nocase wide ascii
		$c32="brute" nocase wide ascii
		$c33="dump" nocase wide ascii
		$c34="StringDecryptor" nocase wide ascii
		$c35="wireshark" nocase wide ascii
		$c36="debugger" nocase wide ascii
		$c37="httpdebugger" nocase wide ascii
		$c38="gdb" nocase wide ascii
		$c39="kdb" nocase wide ascii
		$c40="x64_dbg" nocase wide ascii
		$c41="windbg" nocase wide ascii
		$c42="x64netdumper" nocase wide ascii
		$c43="petools" nocase wide ascii
		$c44="megadumper" nocase wide ascii
		$c45="reversal" nocase wide ascii
		$c46="ksdumper 1.1-by equifox" nocase wide ascii
		$c47="dbgclr" nocase wide ascii
		$c48="HxD" nocase wide ascii
		$c49="monitor" nocase wide ascii
		$c50="peek" nocase wide ascii
		$c51="ollydbg" nocase wide ascii
		$c52="ksdumper" nocase wide ascii
		$c53="http" nocase wide ascii
		$c54="wpe pro" nocase wide ascii
		$c55="dbg" nocase wide ascii
		$c56="httpanalyzer" nocase wide ascii
		$c57="httpdebug" nocase wide ascii
		$c58="PhantOm" nocase wide ascii
		$c59="kgdb" nocase wide ascii
		$c60="james" nocase wide ascii
		$c61="x32_dbg" nocase wide ascii
		$c62="proxy" nocase wide ascii
		$c63="phantom" nocase wide ascii
		$c64="mdbg" nocase wide ascii
		$c65="WPE PRO" nocase wide ascii
		$c66="system explorer" nocase wide ascii
		$c67="de4dot" nocase wide ascii
		$c68="x64dbg" nocase wide ascii
		$c69="X64NetDumper" nocase wide ascii
		$c70="protection_id" nocase wide ascii
		$c71="charles" nocase wide ascii
		$c72="systemexplorer" nocase wide ascii
		$c73="pepper" nocase wide ascii
		$c74="hxd" nocase wide ascii
		$c75="procmon64" nocase wide ascii
		$c76="MegaDumper" nocase wide ascii
		$c77="ghidra" nocase wide ascii
		$c78="xd" nocase wide ascii
		$c79="0harmony" nocase wide ascii
		$c80="dojandqwklndoqwd" nocase wide ascii
		$c81="hacker" nocase wide ascii
		$c82="process hacker" nocase wide ascii
		$c83="SAE" nocase wide ascii
		$c84="mdb" nocase wide ascii
		$c85="checker" nocase wide ascii
		$c86="harmony" nocase wide ascii
		$c87="Protection_ID" nocase wide ascii
		$c88="PETools" nocase wide ascii
		$c89="scyllaHide" nocase wide ascii
		$c90="x96dbg" nocase wide ascii
		$c91="systemexplorerservice" nocase wide ascii
		$c92="folder" nocase wide ascii
		$c93="mitmproxy" nocase wide ascii
		$c94="dbx" nocase wide ascii
		$c95="sniffer" nocase wide ascii
		$c96="http toolkit" nocase wide ascii
		$c97="process hacker 2" nocase wide ascii
		$c98="scyllahide" nocase wide ascii
		
	condition:
		
		($a1 or $a2) or ($b1 or $b2) and any of ($c*)		
}