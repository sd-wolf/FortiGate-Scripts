###################################################################################################
# FortiAnalyzer Device Reporting Tool                                                             #
# Date: 5th February 2022                                                                         #
# Some initial code from another person, thanks to him for that initial code!                     #
###################################################################################################

### Set execution policy to allow PS to run.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force    
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force 

### Enable Tls 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

### Variable declaration for report export.
$faz_csv_filename = 'faz_device_report.csv'

### Information for user running the script.
write-output ""
write-output "This script will connect to multiple FortiAnalyzers and report on the number of devices that are configured on the FortiAnalyzers."
write-output ""

### Prompt the user to specify the number of FortiAnalyzers
[uint16]$faz_count = Read-Host "Please enter the number of FortiAnalyzers"

if (!$faz_count) {
    Throw 'A valid number was not provided. Please provide a number such as "3".'
}

### Collection of FortiAnalyzer settings that the script will use to collect data.
$faz_settings = @()

write-output ""
for ($i=1; $i -le $faz_count; $i++) {
    $faz_record = [ordered] @{
        "ip" = ""
        "username" = ""
        "password" = ""
    }
    $faz_settings += $faz_record
    write-output "#####################################"
    write-output "### FortiAnalyzer $($i) Configuration ###"
    write-output "#####################################"
    $faz_ip = Read-Host "Please enter the IP or FQDN of FortiAnalyzer $i"
    $faz_username = Read-Host "Please enter the username for FortiAnalyzer $i"
    $faz_password = Read-Host "Please enter the password for FortiAnalyzer $i" -AsSecureString
    $faz_index = $i -1
    $faz_settings[$faz_index].ip = $faz_ip
    $faz_settings[$faz_index].username = $faz_username
    $faz_settings[$faz_index].password = $faz_password
    write-output ""
}

function Connect-FAZ-Logon {
    ### This function is used to authenticate with the FortiAnalyzer and create a session key that is used for all subsequent session keys.
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $faz_ip,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $faz_username,
        [Parameter(Mandatory=$true, Position=2)]
        [SecureString] $faz_password
    )

    $faz_logon_url = "https://$($faz_ip)/jsonrpc"

### Create JSON body for logon
$json_logon_body = @"
{
    "session" : 1,
    "id" : 1,
    "method" : "exec",
    "params" : [
        {
            "url" : "sys/login/user",
            "data" : [
                {
                    "user" : "$($faz_username)",
                    "passwd" : "$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($faz_password)))"
                }
            ]
        }
    ]
}
"@

### Send API call to create session key for subsequent API calls
$fortitokenrequest = Invoke-RestMethod -Uri $faz_logon_url -Body $json_logon_body -ContentType 'application/json' -Method Post
$accesstoken = $fortitokenrequest.session
#write-output "This is url: $($faz_logon_url)"
#write-output "This is user: $($faz_username)"
#write-output "This is output: $($json_logon_body))"
return $accesstoken
}

function Get-Devices {
    ###
    ### This function is used to connect to a FortiAnalyzer and pull the device information from the FortiAnalyzer's Device Management Database.
    ###
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $faz_ip,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $faz_session_key
    )
    $faz_logon_url = "https://$($faz_ip)/jsonrpc"
### Creating JSON body for collecting devices on FortiManager
$json_devices_body = @"
{
    "id": "1",
    "method": "get",
    "params": [
        {
            "option" : [
                "extra info"
            ],
            "url": "/dvmdb/device"
        }
    ],
    "session": "$faz_session_key"
}
"@

### Send API call to collect list of devices on FortiManager
$device_list = Invoke-RestMethod -Uri $faz_logon_url -Body $json_devices_body -ContentType 'application/json' -Method Post

return $device_list
}

function Select-FortiGates {
    ###
    ### This function is used to identify FortiGates from a device list and then collate the information necessary for the report.
    ###
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $faz_ip,
        [Parameter(Mandatory=$true, Position=1)]
        [PSCustomObject] $device_data
    )
    $fgt_data =@()
    $sorted_data = @()
    foreach ($i in $device_data.result.data) {
        if ($i.os_type -eq 0) {
            $sorted_data += $i
        }
    }    
    foreach ($i in $sorted_data) {
        $index_value = [array]::IndexOf($sorted_data, $i)
        if ($i.os_type -eq 0) {
            $fgt_records = [ordered] @{
                "Name" = ""
                "ADOM" = ""
                "Model" = ""
                "IP" = ""
                "Version" = ""
                "Serial Number" = ""
                "HA Serial Numbers" = ""
                "FortiAnalyzer" = ""
                "Connection Status" = ""
            }
            $fgt_data += $fgt_records
            $fgt_data[$index_value].Name = $i.name
            $fgt_data[$index_value].ADOM = $i.'extra info'.adom
            $fgt_data[$index_value].Model = $i.platform_str
            $fgt_data[$index_value].IP = $i.ip
            $fgt_data[$index_value].Version = "$($i.os_ver).$($i.mr).$($i.patch)"
            $fgt_data[$index_value].'Serial Number' = $i.sn
            if ($i.ha_slave) {
                if ($i.ha_slave.Length -gt 1) {
                    foreach ($j in $i.ha_slave) {
                        $ha_sn = ""
                        if ($j.sn -ne $i.sn) {
                            if ($ha_sn.Length -ne 0) {
                                $ha_sn += " "
                            }
                            $ha_sn += $j.sn
                        }
                    }
                $fgt_data[$index_value].'HA Serial Numbers' = $ha_sn
                } else {
                    $fgt_data[$index_value].'HA Serial Numbers' = "None"
                }
            } else {
                $fgt_data[$index_value].'HA Serial Numbers' = "N/A"
            }
            $fgt_data[$index_value].FortiAnalyzer = $faz_ip
            $fgt_data[$index_value].'Connection Status' = "Offline"
        }
    }
    return $fgt_data
}

function Get-FortiGate-Status {
    ###
    ### This function is used to connect to a FortiAnalyzer and pull the most recent elog.log for each serial number within the last day. 
    ### The presence of an elog.log indicates that the FortiGate logged to the FortiAnalyzer in the last day.
    ### Note: There is a better method for this, but it requires a FortiAnalyzer to be on 6.4+. This was written for backwards compatability to 6.0.
    ###
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $faz_ip,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $faz_session_key,
        [Parameter(Mandatory=$true, Position=2)]
        [Object] $input_data
    )

    $faz_logon_url = "https://$($faz_ip)/jsonrpc"
    
    #$online_fgt_data = @()
    $yesterdaysdate = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss")
    $todaysdate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    $adom_list = @()
    $adom_data = @()

    foreach ($i in $input_data) {
        if (-Not ($adom_list -contains $i.ADOM )) {
            $adom_list += $i.ADOM
        }
    }

    foreach ($i in $adom_list) {
        $index_value = [array]::IndexOf($adom_list, $i)
        $json_online_body = @"
{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "get",
    "params": [
        {
            "apiver": 3,
            "devid": "",
            "url": "/logview/adom/$($i)/logfiles/state", 
            "time-range": {
                "start": "$yesterdaysdate",
                "end": "$todaysdate"
            },
            "filename": "elog.log"  
      }
    ],
    "session": "$faz_session_key"
}
"@
        $online_data = Invoke-RestMethod -Uri $faz_logon_url -Body $json_online_body -ContentType 'application/json' -Method Post
        #$online_fgt_data += $online_data
        
        $adom_records = [ordered] @{
            "ADOM" = ""
            "Data" = ""
        }
        $adom_data += $adom_records
        $adom_data[$index_value].ADOM = $i
        $adom_data[$index_value].Data = $online_data.result.'device-file-list'
    }

    foreach ($i in $input_data) {
        $index_value = [array]::IndexOf($input_data, $i)
        foreach ($j in $adom_data) {
            if ($j.ADOM -eq $i.ADOM) {
                $adom_index_value = [array]::IndexOf($adom_data.ADOM, $j.ADOM)
                $match = $false
                foreach ($k in $adom_data[$adom_index_value].Data) {
                    if ($i.Name -eq $k.'device-name') {
                        $match = $true
                    }
                }
                if ($match) {
                    $input_data[$index_value].'Connection Status' = "Online"
                } else {
                    $input_data[$index_value].'Connection Status' = "Offline"
                }
            }
        }
    }
    return $input_data
}


###################################################################################################
### Main code - Loops through the configuration for each FortiAnalyzer, and for each FortiAnalyzer:
### - Logs into the FortiAnalyzer,
### - Gets all of the devices from the Device Management Database,
### - Selects only FortiGates from the device list, and returns the Name, ADOM, Model, IP Address, Version, Serial Number, HA Serial Number (if applicable), and FortiAnalyzer that it was found on.
### - Queries for any elog.log files within the last two days in each ADOM. If there are, then the Online status is populated
### The data is then combined together into a single output, and exported as a CSV file.
###################################################################################################

$final_output = @()
foreach ($i in $faz_settings) {
    $index_value = [array]::IndexOf($faz_settings, $i)
    $faz_index = $index_value + 1
    write-output "[Starting Data Collection for FortiAnalyzer $faz_index]"
    write-output "[Creating Session Key]"
    $faz_token = Connect-FAZ-Logon $i.ip $i.username $i.password
    write-output "[Collecting Device Information]"
    $devices = Get-Devices $i.ip $faz_token
    write-output "[Sorting Device Information]"
    $output_data = Select-FortiGates $i.ip $devices
    write-output "[Getting Connection Status of Devices]"
    $output_data_with_status = Get-FortiGate-Status $i.ip $faz_token $output_data
    if ($faz_index -gt 1) {
        write-output "[Combining Device Information with Previous Data]"
    }
    foreach ($j in $output_data_with_status) {
        $final_output += $j
    }
    write-output ""
}
write-output "[Exporting Data to $($faz_csv_filename)]"
$final_output = $final_output | ConvertTo-Json | ConvertFrom-Json
$final_output | Export-Csv -NoTypeInformation -Path $faz_csv_filename
write-output ""
write-output "[FortiAnalyzer Report Complete]"

