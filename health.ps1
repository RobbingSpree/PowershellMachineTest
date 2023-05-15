#Created by Janksmith (Bob Tester)
#This tool requires CommandCam executable to be in the same folder as the main script
#CommandCam can be downloaded from here: https://batchloaf.wordpress.com/commandcam/

using namespace System.Management.Automation.Host

cls
$index = 0
$heading = 'Laptop Functionality Tester Tool'

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
if ($admin -ne "True") {
	Write-Host You will need to run this script as admin to remove user accounts -ForegroundColor Red -BackgroundColor White
}

function New-Menu {
	#initial function setup
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
    )
    
	#choice defenitions
    #$generic = [ChoiceDescription]::new('&Variable', 'Label text')
	$cam = [ChoiceDescription]::new('&Cam', 'Run Camera Test')
    $ports = [ChoiceDescription]::new('&Ports', 'Run Ports Test')
    $batt = [ChoiceDescription]::new('&Battery', 'Run Battery Report')
	$wifi = [ChoiceDescription]::new('&WiFi', 'Wi-Fi Functionality Report')
	$user = [ChoiceDescription]::new('&Destroy', 'User Destruction Tool')
	
	$next = [ChoiceDescription]::new('&Next', 'Next Test')
	$exit = [ChoiceDescription]::new('&Exit', 'Exit Tool')

	#list defenition
    $options = [ChoiceDescription[]]($cam, $ports, $batt, $wifi, $user, $next, $exit)

	#this is just used to call the above data
    $result = $host.ui.PromptForChoice($Title, $Question, $options, $index)
	
	#result call
    switch ($result) {
        0 { 'Camera Test Function'; Camera-Test }
        1 { 'This is the Ports Test Tool'; Ports-Test }
        2 { 'Battery Diagnostic Report'; Battery-Test }
        3 { 'Wi-Fi Functionality Report'; Wifi-Test }
		4 { 'This is the User Removal Tool'; User-Remover }
		5 {  
				$index = $index + 1
				if ($index -ge 5) {$index = 6 } 
			}
		6 { Exiter }
    }
	
	#screen cleanup and recursive function call
	
	if ($result -ne 5) {
		#press any key to continue function
		Write-Host -NoNewLine 'Press any key to continue...';
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		cls
		Recursive-Call
	}
}

function Recursive-Call {
	New-Menu -Title $heading -Question 'Which Tool would you like to run?'
}

function switch-itterater {
	#a duplicate of the above switch statement using the index value instead of the value the user selected
	#result call
    switch ($index) {
        0 { 'Camera Test Function'; Camera-Test }
        1 { 'This is the Ports Test Tool'; Ports-Test }
        2 { 'Battery Diagnostic Report'; Battery-Test }
		3 { 'This is the User Removal Tool'; User-Remover }
		4 { 'this value is left blank on purpose' }
		5 { Exiter }
    }
	
}

function Camera-Test {
	#function left blank on purpose
	#https://batchloaf.wordpress.com/commandcam/
	
	#get current user enviroment
	$loc = [Environment]::GetFolderPath("Desktop")
	#check if test file already exists and delete it
	$fn = $loc+"\cam.bmp"
	if(Get-Item -Path $fn -ErrorAction Ignore) {
		Remove-Item $fn
	}
	
	#detect connected webcams
	Write-Host Visible Webcam devices
	Get-WmiObject Win32_PnPEntity | where {$_.caption -match 'camera'} | Select Caption, Status | Format-Table
	
	#instruct user to have laptop open and webcam active
	Write-Host "Normally the default webcam is called Intergrated Webcam" 
	Write-Host "If an IR camera is present it's used for depth sensing used in background removal features"
	Write-Host "We'll now perform a test on the main webcam functionality"
	Write-Host "Please ensure the laptop is open and the webcam is uncovered"
	Write-Host
	sleep 5
	Write-Host -NoNewLine 'Press any key to begin...';
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	
	#launch tool
	.\CommandCam.exe /preview /filename $loc\cam.bmp
	Write-Host "Snapshot aquired"	
	#read details of file
	if(Get-Item -Path $fn -ErrorAction Ignore) {
		
	}
	$index = 1;
}

function Ports-Test {
	#function left blank on purpose
	
	#current ports test is a visual inspection by technician
	Write-Host "================================"
	Write-Host This test is a visual inspection
	Write-Host of the ports of this machine
	Write-Host use your eyes to check for junk
	Write-Host "================================"
	Write-Host
	
	#exits on caps lock press
	Write-Host Press Caps Lock to exit this test
	While ($KeyInfo.VirtualKeyCode -ne 20) {
		$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
		if ($KeyInfo.VirtualKeyCode -eq 20) {
			Write-Host Wrong Key
		}
	}
	$index = 2
}

function Battery-Test {
	#get current user enviroment
	$loc = [Environment]::GetFolderPath("Desktop")
	#check if report file already exists and delete it
	$fn = $loc+"\report.html"
	if(Get-Item -Path $fn -ErrorAction Ignore) {
		Remove-Item $fn
	}
	#pass to powercfg tool for output location
	powercfg /batteryreport /output $loc\report.html
	#start process to pull useful data out of html report
	$Source = Get-Content "$loc\report.html" -Raw
    $HTML = New-Object -Com "HTMLFile"
    $HTML.IHTMLDocument2_write($Source)
	for ($i = 0; $i -lt 10; $i++) {
	    $HTML.body.getElementsByTagName('table')[$i] | % {
			if ($i -eq 5) {
				$data = ConvertFrom-HTMLTable $_ 
			}
		}
    }
	$data | Format-Table
	$index = 3
}

function WiFi-Test {
	#function left blank on purpose
	
	Write-Host "================================"
	Write-Host Currently preping wifi scan
	Write-Host "Don't use the mouse for a bit" 
	Write-Host "================================"
	sleep 1
	explorer.exe ms-availablenetworks: 
	sleep 3
	
	#snippet taken from https://woshub.com/check-wi-fi-signal-strength-windows/
	$logs=@()
	$date=Get-Date
	$cmd=netsh wlan show networks mode=bssid
	$n=$cmd.Count
	For($i=0;$i -lt $n;$i++) {
		If($cmd[$i] -Match '^SSID[^:]+:.(.*)$') {
			$ssid=$Matches[1]
			$i++
			$bool=$cmd[$i] -Match 'Type[^:]+:.(.+)$'
			$Type=$Matches[1]
			$i++
			$bool=$cmd[$i] -Match 'Authentication[^:]+:.(.+)$'
			$authent=$Matches[1]
			$i++
			$bool=$cmd[$i] -Match 'Cipher[^:]+:.(.+)$'
			$chiffrement=$Matches[1]
			$i++
			While($cmd[$i] -Match 'BSSID[^:]+:.(.+)$') {
				$bssid=$Matches[1]
				$i++
				$bool=$cmd[$i] -Match 'Signal[^:]+:.(.+)$'
				$signal=$Matches[1]
				$i++
				$bool=$cmd[$i] -Match 'Type[^:]+:.(.+)$'
				$radio=$Matches[1]
				$i++
				$bool=$cmd[$i] -Match 'Channel[^:]+:.(.+)$'
				$Channel=$Matches[1]
				$i=$i+2
				$logs+=[PSCustomObject]@{date=$date;ssid=$ssid;Authentication=$authent;Cipher=$chiffrement;bssid=$bssid;signal=$signal;radio=$radio;Channel=$Channel}
			}
		}
	}
	$cmd=$null
	$logs| Format-Table
	
	Write-Host 
	Write-Host "================================"
	Write-Host Remember to click on this window 
	Write-Host "================================"
	Write-Host
	$index = 5
}

function User-Remover {
	#function setup
	$choice = 0
	$i = -1
	#New user instruction
	Write-Host "Select the user Profile to remove"
	Write-Host
	Write-Host "================================"
	#List of user Profile locations
	Get-WMIObject -ClassName Win32_UserProfile -Filter "special=false and localpath like 'C:\\users\\%'" | ForEach-Object {
		$i = $i + 1
		$str = $_.localpath.TrimStart("C:\Users\")
		Write-Host $i - $str
	}
	
	#edge case check for more than sensible limit of targets, unable to process multi digit responses
	$max = $i
	if ($max -ge 10) { 
		$max = 9
		Write-Host "**********************************************"
		Write-Host "More than 10 accounts found"
		Write-Host "Only the first 10 options are valid targets"
		Write-Host "**********************************************"
		Write-Host
	}
	Write-Host "================================"
	Write-Host
	Write-Host "Select a value between 0 and "$max
	Write-Host
	Write-Host "================================"
	
	#example code
	#
	#While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
    #	$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
    #}
	
	#snags user choice, need to adjust so it only accepts values between 0 and 9 (48 and 57 in ASCII)
	$choice = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	$choice = $choice.VirtualKeyCode - 48
	#using user value load WMI Object into variable for target purposes
	$target = 0
	$i = 0
	Get-WMIObject -ClassName Win32_UserProfile -Filter "special=false and localpath like 'C:\\users\\%'" | ForEach-Object {
		if (($i -eq $choice) -and ($target -eq 0)) {
			$target = $_		
		}	
		if ($target -eq 0) { $i = $i + 1 }
	}
	$str = $target.localpath.TrimStart("C:\Users\")

	#check for bad user input
	if ($i -gt $max) {
		Write-Host You have made and INVALID choice
		Write-Host -NoNewLine 'Press any key to return to the menu...';
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		cls
		Recursive-Call
	}
	
	#check if user selected is currently logged In
	$error = $env:username
	if ( $error -eq $str ) {
		Write-Host "You have selected the current User" -ForegroundColor Red -BackgroundColor White
		Write-Host "Attempting to delete the current user will cause stability issues" -ForegroundColor Red -BackgroundColor White
		$WarningPreference = "Stop"
		Write-Warning "This action is not advised." -WarningAction Inquire
	}
	
	#confirm choice
	Write-Host
	Write-Host "You have selected" -ForegroundColor Red -BackgroundColor White
	Write-Host $str -ForegroundColor Red -BackgroundColor White
	Write-Host 
	Write-Warning "This action will delete the local user account of the above path." -WarningAction Inquire
	Write-Host 
	
	#act on confirmation
	$UserProfile = Get-WmiObject Win32_UserProfile -ComputerName localhost -filter "LocalPath Like 'C:\\users\\$str'"
	$UserProfile.Delete()
	Write-Host 
	Write-Host "*****************"
	Write-Host "User files for " $str "have been deleted"
	Write-Host "*****************"
	Write-Host
	
	$index = 5
	
}

function ConvertFrom-HTMLTable {
    <#
	Aquired from https://github.com/ztrhgf/useful_powershell_functions/blob/master/ConvertFrom-HTMLTable.ps1
    .SYNOPSIS
    Function for converting ComObject HTML object to common PowerShell object.
    .DESCRIPTION
    Function for converting ComObject HTML object to common PowerShell object.
    ComObject can be retrieved by (Invoke-WebRequest).parsedHtml or IHTMLDocument2_write methods.
    In case table is missing column names and number of columns is:
    - 2
        - Value in the first column will be used as object property 'Name'. Value in the second column will be therefore 'Value' of such property.
    - more than 2
        - Column names will be numbers starting from 1.
    .PARAMETER table
    ComObject representing HTML table.
    .PARAMETER tableName
    (optional) Name of the table.
    Will be added as TableName property to new PowerShell object.
    .EXAMPLE
    $pageContent = Invoke-WebRequest -Method GET -Headers $Headers -Uri "https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files"
    $table = $pageContent.ParsedHtml.getElementsByTagName('table')[0]
    $tableContent = @(ConvertFrom-HTMLTable $table)
    Will receive web page content >> filter out first table on that page >> convert it to PSObject
    .EXAMPLE
    $Source = Get-Content "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html" -Raw
    $HTML = New-Object -Com "HTMLFile"
    $HTML.IHTMLDocument2_write($Source)
    $HTML.body.getElementsByTagName('table') | % {
        ConvertFrom-HTMLTable $_
    }
    Will get web page content from stored html file >> filter out all html tables from that page >> convert them to PSObjects
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.__ComObject] $table,

        [string] $tableName
    )

    $twoColumnsWithoutName = 0

    if ($tableName) { $tableNameTxt = "'$tableName'" }

    $columnName = $table.getElementsByTagName("th") | % { $_.innerText -replace "^\s*|\s*$" }

    if (!$columnName) {
        $numberOfColumns = @($table.getElementsByTagName("tr")[0].getElementsByTagName("td")).count
        if ($numberOfColumns -eq 2) {
            ++$twoColumnsWithoutName
            Write-Verbose "Table $tableNameTxt has two columns without column names. Resultant object will use first column as objects property 'Name' and second as 'Value'"
        } elseif ($numberOfColumns) {
            #Write-Warning "Table $tableNameTxt doesn't contain column names, numbers will be used instead"
            $columnName = 1..$numberOfColumns
        } else {
            throw "Table $tableNameTxt doesn't contain column names and summarization of columns failed"
        }
    }

    if ($twoColumnsWithoutName) {
        # table has two columns without names
        $property = [ordered]@{ }

        $table.getElementsByTagName("tr") | % {
            # read table per row and return object
            $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
            if ($columnValue) {
                # use first column value as object property 'Name' and second as a 'Value'
                $property.($columnValue[0]) = $columnValue[1]
            } else {
                # row doesn't contain <td>
            }
        }
        if ($tableName) {
            $property.TableName = $tableName
        }

        New-Object -TypeName PSObject -Property $property
    } else {
        # table doesn't have two columns or they are named
        $table.getElementsByTagName("tr") | % {
            # read table per row and return object
            $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
            if ($columnValue) {
                $property = [ordered]@{ }
                $i = 0
                $columnName | % {
                    $property.$_ = $columnValue[$i]
                    ++$i
                }
                if ($tableName) {
                    $property.TableName = $tableName
                }

                New-Object -TypeName PSObject -Property $property
            } else {
                # row doesn't contain <td>, its probably row with column names
            }
        }
    }
}

function Other-Test {
	#function left blank on purpose
}

function Exiter {
	exit
}

New-Menu -Title $heading -Question 'Which Tool would you like to run?'