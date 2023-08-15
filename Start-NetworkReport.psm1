<#

TODO:
- Get "Get-WMIObject" working as normal user (figure out how to set permissions on the namespace)

Metrics and Indicators to Report on:
•	(Toughbooks Only) Check for existence of Sierra Wireless service (disable if needed), check for other broadband software like VZAccess Manager or AirCard watcher
•	Checking if Wi-Fi is enabled, or if Airplane mode is enabled (and disabling Airplane mode if need be)
•   Add or check for Wi-Fi connection

Add hyperlinks to locally-saved images to instruct user on self-troubleshooting

This script should be able to be run from the Ninja task tray context menu

Consider modifying the script so it checks Ethernet status, then Wi-Fi, then Broadband in order to avoid showing failures despite having an active connection. This will avoid confusion for the user.
#>

#Region Static Environment Variables
$vpnClient = "WireGuard"
$reportDirectory = "$env:USERPROFILE\Desktop\"
$reportFileName = "NetworkReport.html"
$reportFilePath = "$reportDirectory"+"$reportFileName"
$deviceModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
#endRegion

#Region Dynamic Variables (must be addressed using script:)
$script:systemInfo = @($null) #Should contain Name, Result, Status, and Details
$script:wifiAdapter
#endregion

#Region Declare Object Class(es)
class systemInfo
{
    [string]$Name
    [string]$Result #Passed, Failed, or N/A
    [string]$Status
    [string]$Details
}
#endregion

#Region Supporting Functions
function Get-WireGuardInstallState
{
    $software = $vpnClient;
    $installed = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $software })
    $isInstalled = $false

    If(-Not $installed)
    {
        Write-Host "'$software' is NOT installed."
        $script:systemInfo += [systemInfo]@{Name="WireGuard VPN Installation"; Result="Failed"; Status="Not Installed"; Details="The WireGuard VPN is not installed. This is a problem if you're not connected with a physical cable or through the Wi-Fi."}
    }
    else
    {
        Write-Host "'$software' is installed."
        $script:systemInfo += [systemInfo]@{Name="WireGuard VPN Installation"; Result="Passed"; Status="Installed"; Details="The WireGuard VPN is installed. This provides a tunnel back to the network."}
        $isInstalled = $true
    }
    return $isInstalled
}

function Get-VPNState
{
    $interface = Test-NetConnection -ComputerName "wireguard.com"
    if (($interface.InterfaceAlias -like "*Privledged*") -or ($interface.InterfaceAlias -like "*_$($env:ComputerName)")) {
        Write-Host "VPN Running"
        $script:systemInfo += [systemInfo]@{Name="VPN Connection"; Result="Passed"; Status="Running"; Details="WireGuard active."}        
    }
    else {
        Write-Host "No VPN currently running"
        $script:systemInfo += [systemInfo]@{Name="VPN Connection"; Result="Failed"; Status="Not Running"; Details="WireGuard Not Currently Running"}
    }
}

function Test-DomainConnection
{
    if ((Test-NetConnection $domain).PingSucceeded -eq $True)
    {
        Write-Output "Connection to $domain has been verified."
        $script:systemInfo += [systemInfo]@{Name="$domain Connection"; Result="Passed"; Status="Connected"; Details="You're successfully connected to the network. Your network drives, printers, etc. should all be accessible."}
    }
    else
    {
        Write-Output "Connection to $domain has failed."
        $script:systemInfo += [systemInfo]@{Name="$domain Connection"; Result="Failed"; Status="Disconnected"; Details="Connecting to the network was unsuccessful."}
    }
}

function Test-InternetConnection
{
    if ((Test-NetConnection 8.8.8.8).PingSucceeded -eq $True) #Tests connection to Google's DNS server
    {
        Write-Output "Connection to Internet has been verified."
        $script:systemInfo += [systemInfo]@{Name="Internet Connection"; Result="Passed"; Status="Connected"; Details="You're connected to the Internet. If you're experiencing issues, ensure $vpnClient is connected. Otherwise, there may be an issue with the system you're trying to access."}
    }
    else
    {
        Write-Output "Connection to Internet has failed."
        $script:systemInfo += [systemInfo]@{Name="Internet Connection"; Result="Failed"; Status="Disconnected"; Details="Connecting to the Internet was unsuccessful. Make sure your Broadband, Wi-Fi, or Ethernet connection is up."}
    }
}

function Get-LoggedOnUsers
{
    Write-Host "Sessions on $env:COMPUTERNAME"
    qwinsta.exe
}

function Get-EthernetStatus
{
    #Identifies the Ethernet Network Adapter by searching for the following keywords in the Interface Description: wireless, wifi, wi-fi, wlan 
    $ethernetAdapter = (Get-NetAdapter | Where-Object {($_.InterfaceDescription -like "*ethernet*") -or ($_.InterfaceDescription -like "*wired*") -or ($_.InterfaceDescription -like "*lan*")})

    if ($ethernetAdapter.Status -eq "Up")
    {
        Write-Host "Wired Ethernet connection is Up."
        $script:systemInfo += [systemInfo]@{Name="Ethernet Connection"; Result="Passed"; Status="Connected"; Details="Your wired Ethernet connection is Up."}
    }
    else
    {
        Write-Host -NoNewLine "Wired Ethernet connection is Down."
        $script:systemInfo += [systemInfo]@{Name="Ethernet Connection"; Result="Failed"; Status="Disconnected"; Details="Your wired Ethernet connection is Down. Ethernet will only be Up if you plugged a network cable in or you're docked in at the office."}
    }
}

function Get-BroadbandInfo
{
    # Obtain the broadband model
    # $h = Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" -ClassName MDM_DeviceStatus_CellularIdentities01_01
    $interface = Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like "Cellular*" -and $_.AddressFamily -eq "IPv4"}
    $adapter = Get-NetAdapter | Where-Object {$_.Name -like "*Cellular*" -and $_.Status -ne "Not Present"}
    $ourFirmware = netsh mbn sh interface
    $SIM = netsh mbn show read i=*

    # Determine if the broadband characteristics are present
    if ($null -eq $interface -and $null -eq $adapter)
    {
        Write-Host "Broadband card nonexistent."
        [systemInfo]$model = @{Name="Broadband model"; Result="Failed"; Status="Not Present"; Details="This device doesn't have a broadband card assigned to it."}
        [systemInfo]$sim = @{Name="SIM Card"; Result="Failed"; Status="Not Present"; Details="This device doesn't have a SIM Card assigned to it."}
        [systemInfo]$phonenumber = @{Name="Phone number"; Result="Failed"; Status="Not Present"; Details="This device doesn't have a phone number assigned to it."}
        [systemInfo]$firmware = @{Name="Firmware"; Result="Failed"; Status="Not Present"; Details="This device doesn't have firmware assigned to it."}
        [systemInfo]$status = @{Name="Status"; Result="Failed"; Status="Not Present"; Details="This device doesn't have broadband assigned to it."}
        [systemInfo]$signal = @{Name="Broadband Signal"; Result="Failed"; Status="Not Present"; Details="This device doesn't have broadband signal"}
        $script:systemInfo += $model
        $script:systemInfo += $sim
        $script:systemInfo += $phonenumber
        $script:systemInfo += $firmware
        $script:systemInfo += $status
        $script:systemInfo += $signal
    }
    else
    {
        Write-Host "Broadband card exists."
        [systemInfo]$model = @{Name="Broadband model"; Result="Passed"; Status="Present"; Details="Broadband Model: $($adapter.InterfaceDescription)"}

        # Determine if a SIM Exists
        $ourSim = $SIM[3] -split ":"
        if (" SIM not inserted" -eq $ourSim[1]) {
            Write-Host "No SIM detected"
            [systemInfo]$sim = @{Name="SIM Card"; Result="Failed"; Status="Not Present"; Details="No SIM Present"} 
            Write-Host "No Valid Phone Number Present"
            [systemInfo]$phonenumber = @{Name="Phone number"; Result="Failed"; Status="Not Present"; Details="No active phone number present"}
        } else {
            Write-Host "SIM Card Inserted"
            [systemInfo]$sim = @{Name="SIM Card"; Result="Passed"; Status="Present"; Details=$SIM[6]}
            $ourNumber = netsh mbn show read i=*
            $dispNum = $ourNumber[8]
            $num = $ourNumber[7] -split ":"
            $numNum = $num[1] -as[int]
            if ($numNum -eq 0) {
                Write-Host "No Valid Phone Number Present"
                [systemInfo]$phonenumber = @{Name="Phone number"; Result="Failed"; Status="Not Present"; Details="No active phone number present"}
            } else {
                Write-Host "Phone Number Present"
                [systemInfo]$phonenumber = @{Name="Phone number"; Result="Passed"; Status="Present"; Details=$dispNum} 
            }       
        }

        # Determine if there is a valid phone number present
        <#$ourNum = $SIM[7] -split ":"
        $numNum = $ourNum -as[int]
        if ($numNum -eq 0) {
            
        } else {
            Write-Host "Phone Number Present"
            $numNum = $SIM[7] -split ":"
            Write-Host $SIM[8]
            [systemInfo]$phonenumber = @{Name="Phone number"; Result="Passed"; Status="Present"; Details=$numNum[1]} 
        }#>

        # Determine if there is firmware present
        if ($null -eq $ourFirmware[15]) {
            Write-Host "No Firmware Present"
            [systemInfo]$firmware = @{Name="Firmware"; Result="Failed"; Status="Not Present"; Details="No Firmware Present"}
        } else {
            Write-Host "Firmware Present"
            [systemInfo]$firmware = @{Name="Firmware"; Result="Passed"; Status="Present"; Details=$ourFirmware[15]}
        }

        # Determine if Broadband is currently connected
        $broadband = $ourFirmware[9] -split ":"
        if ($broadband -eq " Not connected") {
            Write-Host "Broadband Disconnected"
            [systemInfo]$status = @{Name="Broadband Status"; Result="Failed"; Status="Not Present"; Details="Broadband not connected"}        
        } else {
            Write-Host "Broadband connected"
            [systemInfo]$status = @{Name="Broadband Status"; Result="Passed"; Status="Present"; Details="Broadband connected"}
        }

        # Determine Signal Strength
        if ($null -eq $ourFirmware[18]) {
            Write-Host "Signal Strength Not Present"
            [systemInfo]$signal = @{Name="Signal"; Result="Failed"; Status="Not Present"; Details="No Signal Detected"}
        } else {
            $ourSignal = $ourFirmware[18] -split ":"
            if (" 0%" -eq $ourSignal[1]) {
                Write-Host "Signal Strength Not Present"
                [systemInfo]$signal = @{Name="Signal"; Result="Failed"; Status="Not Present"; Details="No Signal Detected"}
            } else {
                Write-Host "Signal Strength Present"
                [systemInfo]$signal = @{Name="Signal"; Result="Passed"; Status="Present"; Details=$ourFirmware[18]}
            }   
        }
        
        # Add everything to network report
        $script:systemInfo += $model
        $script:systemInfo += $sim
        $script:systemInfo += $phonenumber
        $script:systemInfo += $firmware
        $script:systemInfo += $status
        $script:systemInfo += $signal        
    } 
}

function Get-SierraWirelessServiceState
{
    Get-Service "Sierra Wireless"
}

function Get-VZAMState
{
    
}

function Get-AirCardWatcherState
{
    
}

function Get-WiFiStatus
{
    #Get Status of Wi-Fi Network Adapter Enable/Disable
    #use $script:wifiAdapter
    <# Properties of interest:
    Name
    InterfaceDescription
    InterfaceOperationalStatus
    InterfaceName
    AdminStatus
    MediaConnectionState
    ConnectorPresent
    ifName
    ifDesc
    EnabledDefault
    EnabledState
    DriverDescription
    #>

    $ssid = (Get-NetConnectionProfile).Name
    $signal = $null

    if ($script:wifiAdapter.Status -eq "Up")
    {
        Write-Host "Wi-Fi connection is Up."
        $script:systemInfo += [systemInfo]@{Name="Wi-Fi Connection"; Result="Passed"; Status="Connected"; Details="Your Wi-Fi connection is Up. You are connected to $ssid. Signal strength is $signal."}
    }
    else
    {
        Write-Host -NoNewLine "Wi-Fi connection is Down."
        $script:systemInfo += [systemInfo]@{Name="Wi-Fi Connection"; Result="Failed"; Status="Disconnected"; Details="Your Wi-Fi connection is Down. Relocate to a facility."}
    }
}

function Get-WiFiAdapter
{
    #Get State of Window's Wi-Fi Software Enable/Disable
    #Get State of Wi-Fi Network Adapter Enable/Disable
    #Keywords: Wireless, WiFi, Wi-Fi, WLAN
    #(Get-NetAdapter).InterfaceDescription

    <# Properties of interest:
    Name
    InterfaceDescription
    InterfaceOperationalStatus
    InterfaceName
    AdminStatus
    MediaConnectionState
    ConnectorPresent
    ifName
    ifDesc
    EnabledDefault
    EnabledState
    DriverDescription
    #>

    #Identifies the Wi-Fi Network Adapter by searching for the following keywords in the Interface Description: wireless, wifi, wi-fi, wlan 
    $script:wifiAdapter = (Get-NetAdapter | Where-Object {($_.InterfaceDescription -like "*wireless*") -or ($_.InterfaceDescription -like "*wifi") -or ($_.InterfaceDescription -like "*wi-fi*") -or ($_.InterfaceDescription -like "*wlan*")})
    
    if ($null -eq $script:wifiAdapter)
    {
        Write-Host "No Wi-Fi adapter detected."
        $script:systemInfo += [systemInfo]@{Name="Wi-Fi Adapter Presence"; Result="Failed"; Status="Not Present"; Details="No Wi-Fi adapter was detected on this device. It either does not have a Wi-Fi adapter installed or Windows can't see it."}
        return $false
    }
    else
    {
        Write-Host -NoNewLine "Wi-Fi adapter detected."
        $script:systemInfo += [systemInfo]@{Name="Wi-Fi Adapter Presence"; Result="Passed"; Status="Present"; Details="There is a valid Wi-Fi adapter on this device."}
        return $true

        Get-WiFiStatus
    }
}

function Get-AirplaneModeState
{
    return (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\RadioManagement\SystemRadioState").'(default)'
}

function New-Report
{
    #Define the HTML header (CSS) to format the HTML file
    $header = @"
<title>Network Diagnostic Report</title>
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse; font-family: Verdana, sans-serif;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #a3c6ff;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

    $preContent = "<table>
    <tr>
        <td>Username</td>
        <td>$env:USERNAME</td>
    </tr>
    <tr>
        <td>Device Name</td>
        <td>$env:COMPUTERNAME</td>
    </tr>
    <tr>
        <td>Device Model</td>
        <td>$deviceModel</td>
    </tr>
    </table><br>"

    $htmlRaw = $script:systemInfo | ConvertTo-HTML -Head $header -PreContent $preContent #Create a variable containing the raw HTML data from ConvertTo-HTML

    #Write-Host "Here's the raw HTML before adding styles: $htmlRaw"

    $htmlFinal = $htmlRaw | ForEach-Object {$_ -Replace "<td>Passed</td>", "<td bgcolor='#7aff73'><b>Passed</b></td>" -Replace "<td>Failed</td>", "<td bgcolor='#ff4d55'><b>Failed</b></td>"} #Stylize the test results

    #Write-Host "Here's the HTML after adding styles: $htmlFinal"

    $htmlFinal | Out-File -FilePath $reportFilePath -Force #Output the final HTML to a file on the user's desktop

}

function Open-Report
{
    Invoke-Item -Path $reportFilePath #Open the HTML file in their default browser
}
#endRegion

#region Main Functions

function Invoke-DefaultFunctions
{
    Write-Host "Running default sequence of tests. This will skip tests deemed unnecessary in most cases."

    $airplaneStatus = Get-AirplaneModeState

    if ($airplaneStatus -eq 1) {
        Write-Host "Cannot Connect to Internet Because device in airplane mode."
    } else {

        Test-InternetConnection

        Test-DomainConnection

        if (($script:systemInfo | Where-Object -Property Name -eq -Value "$domain Connection").Result -eq "Passed")
        {
            Write-Host "We won't run the NIC tests since we know we're connected to $domain."
        }
        elseif (($script:systemInfo | Where-Object -Property Name -eq -Value "$domain Connection").Result -eq "Failed")
        {
            Write-Host "We're going to run the NIC tests since we cannot connect to $domain."

            Get-EthernetStatus

            Get-WiFiAdapter

            $isVPNInstalled = Get-WireGuardInstallState          
            if ($isVPNInstalled) {
                Get-VPNState
            } 
        }
        else
        {
            Write-Host "Something else went wrong but we're not sure what."
        }

        New-Report

        Open-Report
    }   
}

function Invoke-AllFunctions
{
    Write-Host "Running all tests because the -All parameter was used."

    $airplaneStatus = Get-AirplaneModeState

    if ($airplaneStatus -eq 1) {
        Write-Host "Cannot Connect to Internet Because device in airplane mode."
    } else {

        Test-InternetConnection

        Test-DomainConnection

        Get-EthernetStatus

        Get-WiFiAdapter

        $isVPNInstalled = Get-WireGuardInstallState
        if ($isVPNInstalled) {
            Get-VPNState
        } 

        Get-BroadbandInfo

        New-Report

        Open-Report
    }  
}

function Start-NetworkReport
{
    param
    (
    [switch]$All #If the -All parameter is used, it will be set to true. This is a boolean "switch parameter"
    )

    $script:systemInfo = @($null) #This is necessary to reset the data in the report on rerun

    if ($All -eq $true)
    {
        Invoke-AllFunctions
    }
    else
    {
        Invoke-DefaultFunctions
    }
}

#endregion
export-modulemember -Function Start-NetworkReport