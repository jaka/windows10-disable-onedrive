# Disable One Drive in Windows 10
===

Run with administrator privileges 

```
Function Force-New-Item([String]$Path)
{
	If (!(Test-Path $Path)) {
		New-Item -Force -Path $Path
	}
}

Function RemoveAcl([String]$File)
{
	If (!(Test-Path -Path "$File")) {
		Return
	}
	$Acl = Get-Acl $File
	$Acl.SetAccessRuleProtection($true, $true)
	Set-Acl -Path $File -AclObject $Acl

	$Acl = Get-Acl $File
	$Acl.Access | Where-Object { $_.IdentityReference -NotMatch "APPLICATION PACKAGE AUTHORITY" } | ForEach {
		$Acl.RemoveAccessRule($_) 
	}
	Set-Acl -Path $File -AclObject $Acl
}

Function DisableOneDrive
{
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "OneDriveSetup" -Force -ErrorAction SilentlyContinue
	
	$Paths = @("$env:SYSTEMROOT\System32", "$env:SYSTEMROOT\SysWOW64")
	ForEach ($Path in $Paths) {
		$OneDriveSetup = Join-Path -Path $Path -ChildPath "OneDriveSetup.exe"
		if (Test-Path -Path "$OneDriveSetup" -PathType Leaf) {
			Start-Process "$OneDriveSetup" "/uninstall" -NoNewWindow -Wait
			Start-Sleep -s 3
			RemoveAcl "$OneDriveSetup"
		}
	}

	Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2

	# Remove OneDrive from File Explorer
	$OneDrive =	"HKLM:SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
	Force-New-Item -Path "$OneDrive"
	Set-ItemProperty -Path "$OneDrive" -Name "System.IsPinnedToNameSpaceTree" -Type DWORD -Value 0
	$OneDrive =	"HKLM:SOFTWARE\Classes\CLSID\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
	Force-New-Item -Path "$OneDrive"
	Set-ItemProperty -Path "$OneDrive" -Name "System.IsPinnedToNameSpaceTree" -Type DWORD -Value 0
	
	REG LOAD HKU\Default C:\Users\Default\NTUSER.DAT
	Remove-ItemProperty -Path "Registry::HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup"
	REG UNLOAD HKU\Default

	$Roots = @("HKLM:\SOFTWARE", "HKLM:\SOFTWARE\Wow6432Node")
	$SubRoot = "Policies\Microsoft\Windows\OneDrive"
	$NameSpaces = Join-Path -Path $Roots -ChildPath $SubRoot
	ForEach ($OneDrive in $NameSpaces) {
		Force-New-Item -Path $OneDrive
		# Prevent the usage of OneDrive for file storage
		Set-ItemProperty -Path $OneDrive -Name "DisableFileSync" -Type DWORD -Force -Value 1
		# Prevent the usage of OneDrive for file storage
		Set-ItemProperty -Path $OneDrive -Name "DisableFileSyncNGSC" -Type DWORD -Force -Value 1
		# Save documents to OneDrive by default
		Set-ItemProperty -Path $OneDrive -Name "DisableLibrariesDefaultSaveToOneDrive" -Type DWORD -Force -Value 0
	}

	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue 
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue 
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue
	
	$CommonApplicationData = [Environment]::GetFolderPath("CommonApplicationData")
	$Path = Join-Path -Path "$CommonApplicationData" -ChildPath "Microsoft OneDrive"
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Path $Path
}

DisableOneDrive
```
