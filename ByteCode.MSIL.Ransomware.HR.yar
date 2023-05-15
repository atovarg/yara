rule Byte_Code_MSIL_Ransomware_HR
{
	meta:
		Autor= "Alex Tovar"		
	
	strings:
		$a1 = "220212232751Z07"
		$a2 = "H!Gp0" nocase
			
	
	condition:
		$a1 or $a2
}

