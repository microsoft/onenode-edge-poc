[CmdletBinding()] param (
    [Parameter()]
    [String]$ConfigFile='./config.txt'
)
<#---------------------------------------------------------------------------------------------------------------#>
<# 
    Helper function. The re-startability of this script, and the ability to use data here in other Arc Jumpstart
    scenarios depends on storing critical variable data in environment variables. This updates the current session
    as well as the permanent registry values at once.
#>
function Set-Env 
{
    param (
        [String]$Name,
        [String]$Value
    )
    [Environment]::SetEnvironmentVariable($name, $value, "Machine")
    [Environment]::SetEnvironmentVariable($name, $value)
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Helper function. Call only after all other critical steps in an execution stage are done. Updates the
    progress.log file to show current stage is completed.
#>
Function Update-Progress 
{
    $progressLog[$currentStepIndex] = "$currentStepName = Completed"
    $progressLog | Out-File -FilePath '.\progress.log' -Encoding utf8 -Force
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Completed Step:"(($progressLog[$currentStepIndex]).Split())[0] -ForegroundColor DarkGreen
    Write-Host "Next Step:"(($progressLog[$currentStepIndex+1]).Split())[0] -ForegroundColor DarkGreen

}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Helper function. Adds important dynamically generated info to the end of the config.txt file. Values like
    SPN information, access keys, and IP address info get stored for later use.
#>
function Update-ScriptConfig
{
    param 
    (
        [String]$varName,
        [String]$varValue
    )
    Set-Env -Name $varName -Value $varValue
    $varFileOutput = "$varName = $varValue"
    Out-File -FilePath $ConfigFile -Append -Encoding 'utf8' -InputObject $varFileOutput
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Helper function. Called at the very beginning of each execution. Creates new variables from values in
    config.txt. Allows user to edit the values during execution if there is a problem. Overwrites previously
    stored values from earlier executions.
#>
function Initialize-Variables 
{
    # Load our settings into variable from config.txt.  There is no parameter validation currently.
    try 
    {
        $config = ConvertFrom-StringData (Get-Content -Raw $ConfigFile)
        foreach ($i in $config.Keys) 
        {
            New-Variable -Name $i -Value ($config.$i) -Force -Scope Global
            Set-Env -Name $i -Value ($config.$i)
        }
    }
    catch 
    {
        Write-Warning "Could not find or open $ConfigFile"
        Write-Warning "Please verify the file exists in the location specified"
        exit
    }

    $errPref = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Turn off the nag warnings about module migration
    Set-Env -Name "SuppressAzureRmModulesRetiringWarning" -Value "true"
    Set-Env -Name "SuppressAzurePowerShellBreakingChangeWarnings" -Value "true"

    $ErrorActionPreference = $errPref
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Helper function. Returns the network prefix for a given IP and prefix length. Needed to calculate CIDR values 
    elsewhere in the script. Makes getting the correct values into config.txt easier. Ex: 
        Get-NetworkPrefix -ip 172.16.67.44 -prefix 16
        returns 172.16.0.0
#>
function Get-NetworkPrefix {
    param (
        [IPAddress]$ip,
        [Int32]$prefix
    )
    $mask = [IPAddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $prefix))-1)
    return [IPAddress]($ip.Address -band $mask.Address)
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Set the script up to run to completetion. Disables SConfig, enables autologon for the current user, and sets
    itself to run automatically every time PowerShell starts. If you need to start a PS session separately, use the
    -noprofile switch
#>
function EnableAutorun 
{
    # Record start time so we can measure execution time
    Write-Host "ONENODESTART:" (Get-Date).Ticks
    # Disable SConfig for the duration of this script
    Set-SConfig -AutoLaunch $false

    # Set the script to auto-launch
    Out-File -FilePath "$PSHOME\Profile.ps1" -Encoding utf8 -InputObject $PSCommandPath

    # Enable auto-logon so the script can continue running
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
    Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$adminUsername" -type String 
    Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$adminPassword" -type String

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Download and install the minimum required modules to log into Azure. Once you perform the device login, the
    script will run to completion without further user input.
#>
function AzBootstrap
{
    Install-PackageProvider -Name "NuGet" -MinimumVersion 2.8.5.201 -ForceBootstrap -Force -Confirm:$false
    Register-PSRepository -Default 
    Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted" 
    Install-Module -Name "PowershellGet" -Confirm:$false -SkipPublisherCheck -Force
    Install-Module -Name "Az.Resources"
    Install-Module -Name "Az.Accounts"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Most Azure steps will use an SPN identity. This creates the SPN and stores the critical data for later use.
#>
function CreateArcBoxSpn
{
    # Interactive login, requires user input
    Connect-AzAccount `
        -Subscription $subscriptionId `
        -Tenant $tenantId `
        -Scope "CurrentUser" `
        -UseDeviceAuthentication 

    # Create new SPN
    $spnObj = New-AzADServicePrincipal `
        -Role "Contributor" `
        -DisplayName $spnDisplayName `
        -Scope "/subscriptions/$subscriptionId" `
        -Tag @{CreatedBy="OneNodeScript"}        

    # Copy critical info to variables
    $global:spnClientId = $spnObj.AppId
    $global:spnClientSecret = $spnObj.PasswordCredentials.SecretText
    $global:spnTenantId = $spnObj.AppOwnerOrganizationId

    # Save the SPN info
    Update-ScriptConfig -varName "spnClientId" -varValue $spnClientId
    Update-ScriptConfig -varName "spnClientSecret" -varValue $spnClientSecret
    Update-ScriptConfig -varName "spnTenantId" -varValue $spnTenantId

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Install any additional modules used by later stages of the script. Done inside a new PSSession so the correct
    versions of NuGet and PSGet are used.
#>
function InstallAzModules
{
    $session = New-PSSession 
    Invoke-Command -Session $session -ScriptBlock `
    {
        Install-Module -Name "Az.KubernetesConfiguration"
        Install-Module -Name "Az.CustomLocation"
        Install-Module -Name "Az.ConnectedKubernetes"
        Install-Module -Name "Az.OperationalInsights"
        Install-Module -Name "Az.StackHCI"
        Install-Module -Name "AksHci" -Repository "PSGallery" -AcceptLicense -Confirm:$false -Force
    }

    Remove-PSSession -Session $session

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Some functions must be done with the Az CLI, so let's install that now.
#>
function InstallAzCli
{
    # Save to same directory as the script
    $azCliUri = "https://aka.ms/installazurecliwindows"
    $azCliPackage = "./azure-cli.msi"

    # Use BITS to transfer file, for speed and reliability
    Import-Module -Name 'BitsTransfer'
    Start-BitsTransfer -Source $azCliUri -Destination $azCliPackage

    # Run the installer non-interactively, but show progress. Feels nice to see progress, right? 
    Start-Process msiexec.exe -Wait -ArgumentList '/I azure-cli.msi /passive'

    # Make sure the CLI and AKSHCI locations are in the %PATH% because later commands depend on it
    Set-Env -Name Path -Value "$env:Path;C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin;C:\Program Files\AksHci"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function InstallWAC
{
    # Save to same directory as the script
    $azCliUri = "https://aka.ms/wacdownload"
    $azCliPackage = "./wac.msi"

    # Use BITS to transfer file, for speed and reliability
    Import-Module -Name 'BitsTransfer'
    Start-BitsTransfer -Source $azCliUri -Destination $azCliPackage

    # Run the installer non-interactively, but show progress. Feels nice to see progress, right? 
    Start-Process msiexec.exe -Wait -ArgumentList '/I wac.msi /passive SME_PORT=443 SSL_CERTIFICATE_OPTION=generate'

    New-NetFirewallRule -DisplayName "SME" -Direction 'inbound' -Profile 'Any' -Action 'Allow' -LocalPort 80 -Protocol 'TCP'

    Update-Progress
}

<#---------------------------------------------------------------------------------------------------------------#>
<#
    Assign required roles to the SPN. SPN info takes some time to propogate. This ensures time elapses.
#>
function AssignSpnRoles
{
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Security admin" 
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Security reader"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Monitoring Metrics Publisher"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "User Access Administrator"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Azure Connected Machine Onboarding"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Azure Connected Machine Resource Administrator"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Ensure the correct Azure Resource Providers (RPs) are registered in this subscription 
#>
function RegisterHybridProviders
{
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Kubernetes"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.KubernetesConfiguration"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.ExtendedLocation"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridCompute"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.AzureArcData"
    
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Create the Resource Group that will be used by almost everything in later stages of the script
#>
function CreateResourceGroup
{
    New-AzResourceGroup `
        -Name $resourceGroup `
        -Location $azureLocation `
        -Tag @{CreatedBy="OneNodeScript"}

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Log Analytics workspace is used for monitoring and logs for multiple services
#>
function CreateAnalyticsWorkspace
{
    $workspace = @{
        "Name" =  $workspaceName
        "ResourceGroupName" = $resourceGroup
    }
    $workspaceId  = (New-AzOperationalInsightsWorkspace @workspace -Location $azureLocation -Tag @{CreatedBy="OneNodeScript"}).CustomerId
    $workspaceKey = (Get-AzOperationalInsightsWorkspaceSharedKeys @workspace).PrimarySharedKey
    
    Update-ScriptConfig -varName "WORKSPACE_ID" -varValue $workspaceId
    Update-ScriptConfig -varName "WORKSPACE_SHARED_KEY" -varValue $workspaceKey
    
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Configure the Azure Stack HCI base OS itself. These steps need to be done ahead of registering and deploying
    workloads, and will force a reboot at the end. Script will automatically resume.
#>
function ConfigureOS
{
    # Build a list of required features that need to be installed and install them
    $hciFeatures = `
        "BitLocker", `
        "Data-Center-Bridging", `
        "Failover-Clustering", `
        "FS-FileServer", `
        "FS-Data-Deduplication", `
        "NetworkATC", `
        "Hyper-V-PowerShell", `
        "RSAT-AD-Powershell", `
        "RSAT-Clustering-PowerShell", `
        "Storage-Replica"

    Install-WindowsFeature -Name $hciFeatures -IncludeAllSubFeature -IncludeManagementTools
    
    # This allows Hyper-V to install correctly on nested virtualization systems
    Enable-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online -NoRestart

    # Make sure the system trusts itself. Useful for some loopback remoting we'll be doing later
    Set-Item "WSMan:\localhost\Client\TrustedHosts" -Value '*' -Confirm:$false -Force
    
    # Self-explanatory, isn't it?
    Rename-Computer -NewName $nodeName

    #Checking for Domain Membership
    if (
        (Get-ComputerInfo).csdomain -ne "Workgroup")
            {Write-Host "This machine is part of a domain, will maintain domain membership" ;
            New-Variable -Name DomainMembership -Value true}            
    
    elseif (
        (Get-ComputerInfo).csdomain -eq "Workgroup")
        
        {New-Variable  DomainMembership -Value false}
    
    Update-Progress


    # System MUST restart before we continue. Execution will resume on boot.
    Restart-Computer -Force
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Do some dynamic calculation/detection of networks to we can build the VM switch on the right NIC, if there 
    are multiples in a system.
#>
function CreateVmSwitch
{
    # Get all IPv4 addresses on this system
    $ip = Get-NetIPAddress -IPAddress $hciNodeIp

    $nicNetId = Get-NetworkPrefix -ip $ip.IPAddress -prefix $ip.PrefixLength

    $global:cidrNetworkId = "$nicNetId/" + $ip.PrefixLength
    Update-ScriptConfig -varName "cidrNetworkId" -varValue $cidrNetworkId

    $global:aksCloudIpCidr = "$aksCloudAgentIp/" + $ip.PrefixLength
    Update-ScriptConfig -varName "aksCloudIpCidr" -varValue $aksCloudIpCidr
        
    # Build a simple 1-NIC switch and end the foreach loop
    New-VMSwitch `
        -Name "HCI-Uplink" `
        -EnableEmbeddedTeaming $true `
        -AllowManagementOS $true `
        -MinimumBandwidthMode 'Weight' `
        -NetAdapterName (Get-NetAdapter -InterfaceIndex $ip.ifIndex).Name
        
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Specific hostnames get looked up dynamically during installation. Putting them in the local hosts file
    removes the need for either automatic or manual DNS updates.
#>
function UpdateHostsFile { 
    if ($domainmembership -eq "true")
    {
        Write-Verbose -Message "Skipping Local Hosts File Update Process"    
    }
    else {
        # Get the IP for the NIC bound to the VM switch
        $hciNodeIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "vEthernet (HCI-Uplink)").IPAddress

        # Splatting parameters for easy re-use. Splatting is fun!
        $hostsParams =@{
            "Filepath" = "C:\Windows\System32\drivers\etc\hosts"
            "Encoding" = "utf8"
            "Append" = $true
        }

        Out-File @hostsParams -InputObject "$hciNodeIp $nodeName"
        Out-File @hostsParams -InputObject "$hciClusterIp $hciClusterName"
        Out-File @hostsParams -InputObject "$aksCloudAgentIp $akscloudAgentName"

        Update-Progress
    }
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Create the cluster. Using DNS access point to remove the need for Active Directory.
#>
function CreateCluster
{
    #Checking for Domain Membership
    if (
        (Get-ComputerInfo).csdomain -ne "Workgroup")
            {Write-Host "This machine is part of a domain, will maintain domain membership" ;
            New-Variable -Name DomainMembership -Value true}            

    elseif (
        (Get-ComputerInfo).csdomain -eq "Workgroup")
        
        {New-Variable  DomainMembership -Value false}



    if ($domainmembership -eq "false"){
    New-Cluster `
        -Name $hciClusterName `
        -Node $nodeName `
        -StaticAddress $hciClusterIp `
        -AdministrativeAccessPoint 'DNS' `
        -NoStorage
    }

    elseif ($domainmembership -eq "true"){
        New-Cluster `
        -Name $hciClusterName `
        -Node $nodeName `
        -StaticAddress $hciClusterIp `
        -AdministrativeAccessPoint 'ActiveDirectoryAndDns' `
        -NoStorage

    }
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Prepare and create the storage pool to be used for hosting workloads. In a production deployment there needs
    to be multiple disks, but because this is a simple PoC, we can get away with just one data disk.
#>
function EnableS2D 
{
    # Clean out fixed storage devices to prepare for use. THIS IS DESTRUCTIVE.
    Update-StorageProviderCache
    Get-StoragePool | Where-Object IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false 
    Get-StoragePool | Where-Object IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false
    Get-StoragePool | Where-Object IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false
    Get-PhysicalDisk | Reset-PhysicalDisk
    Get-Disk | Where-Object Number -ne $null | Where-Object IsBoot -ne $true | Where-Object IsSystem -ne $true | Where-Object PartitionStyle -ne RAW | ForEach-Object {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    
    # Enable S2D on the new cluster and create a volume
    Enable-ClusterS2D `
        -PoolFriendlyName "S2Dpool" `
        -WarningAction 'SilentlyContinue' `
        -Confirm:$false

    # Set the storage pool redundancy for single-node
    Set-StoragePool `
        -FriendlyName 'S2Dpool' `
        -FaultDomainAwarenessDefault 'PhysicalDisk'

    # Create a simple volume. This is non-prod, so "simple" is sufficient
    New-Volume `
        -StoragePoolFriendlyName "S2Dpool" `
        -FriendlyName "Volume01" `
        -FileSystem 'CSVFS_ReFS' `
        -ResiliencySettingName 'Simple' `
        -UseMaximumSize

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    The registration code for Azure Stack HCI was never designed to run in this kind of non-domain environment.
    In order to make it work as expected, we have to make a couple of changes to remove some dependencies.
#>
function ModifyAzStackHciModule
{
    $psm1File = (Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules" -Filter "Az.StackHCI.psm1" -Recurse).FullName

    # New-PSSession doesn't like this when there's no DNS suffix
    $replaceStr = [Regex]::Escape(' + "." + $ClusterDNSSuffix')
    (Get-Content -Path $psm1File -Raw) -replace $replaceStr,'' | Set-Content -Path $psm1File

    # Temporary workaround to speed past an issue where we always timeout. Saving you 15 minutes!
    $replaceStr = [Regex]::Escape('$ClusterScheduledTaskWaitTimeMinutes = 15')
    (Get-Content -Path $psm1File -Raw) -replace $replaceStr,'$ClusterScheduledTaskWaitTimeMinutes = 0' | Set-Content -Path $psm1File

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Register the Azure Stack HCI cluster with Azure. This allows you run workloads. It also starts the 60-day
    trial period, after which you will be billed for this system. FYI.
#>
function RegisterHciCluster
{
    # Run these commands in a new PSSession. This removes potential module version conflict issues.
    $session = New-PSSession -EnableNetworkAccess
    Invoke-Command -Session $session -ScriptBlock `
    {
        #Connect to Azure inside this new session
        $spnSecStr = ConvertTo-SecureString -String $using:spnClientSecret -AsPlainText -Force
        $spnCredObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $using:spnClientId, $spnSecStr
        Connect-AzAccount -TenantId $using:spnTenantId -Subscription $using:subscriptionId -Credential $spnCredObj -Scope Process -ServicePrincipal

        # Generate access tokens that let us run registration non-interactively
        $armAccessToken = Get-AzAccessToken
        $graphAccessToken = Get-AzAccessToken -ResourceTypeName 'AadGraph'

        Register-AzStackHCI `
            -SubscriptionId $using:subscriptionId `
            -Region $using:azureLocation `
            -ResourceName $using:hciClusterName `
            -ResourceGroupName $using:resourceGroup `
            -ArmAccessToken $armAccessToken.Token `
            -GraphAccessToken $graphAccessToken.Token `
            -AccountId $armAccessToken.UserId `
            -ArcServerResourceGroupName $using:hciArcServersRg `
            -EnableAzureArcServer:$true `
            -Tag @{CreatedBy="OneNodeScript"}
    }

    # Cleanup
    Remove-PSSession -Session $session
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Temporary workaround for an Arc Servers installation issue. This code will likely get removed from a future
    update. Copied from the Az.StackHCI module.
#>
function RunArcAgentTaskManually
{
    $session = New-PSSession -EnableNetworkAccess
    Invoke-Command -Session $session -ScriptBlock `
    {
        $spnSecStr = ConvertTo-SecureString -String $using:spnClientSecret -AsPlainText -Force
        $spnCredObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $using:spnClientId, $spnSecStr
        Connect-AzAccount -TenantId $using:spnTenantId -Subscription $using:subscriptionId -Credential $spnCredObj -Scope Process -ServicePrincipal

        try
        {
            # Params for Enable-AzureStackHCIArcIntegration 
            $AgentInstaller_WebLink                  = 'https://aka.ms/AzureConnectedMachineAgent'
            $AgentInstaller_Name                     = 'AzureConnectedMachineAgent.msi'
            $AgentInstaller_LogFile                  = 'ConnectedMachineAgentInstallationLog.txt'
            $AgentExecutable_Path                    =  $Env:Programfiles + '\AzureConnectedMachineAgent\azcmagent.exe'

            $DebugPreference = 'Continue'

            # Setup Directory.
            $LogFileDir = $env:windir + '\Tasks\ArcForServers'
            if (-Not $(Test-Path $LogFileDir))
            {
                New-Item -Type Directory -Path $LogFileDir
            }

            # Delete log files older than 15 days
            Get-ChildItem -Path $LogFileDir -Recurse | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays(-15))} | Remove-Item

            # Setup Log file name.
            $date = Get-Date
            $datestring = '{0}{1:d2}{2:d2}' -f $date.year,$date.month,$date.day
            $LogFileName = $LogFileDir + '\RegisterArc_' + $datestring + '.log'
        
            Start-Transcript -LiteralPath $LogFileName -Append | Out-Null
            $sourceExists = [System.Diagnostics.EventLog]::SourceExists('HCI Registration')
            if(-not $sourceExists)
            {
                New-EventLog -LogName Application -Source 'HCI Registration'
            }
            Write-Information 'Triggering Arc For Servers registration cmdlet'
            $arcStatus = Get-AzureStackHCIArcIntegration

            if ($arcStatus.ClusterArcStatus -eq 'Enabled')
            {
                $nodeStatus = $arcStatus.NodesArcStatus
        
                if ($nodeStatus.Keys -icontains ($env:computername))
                {
                    if ($nodeStatus[$env:computername.ToLowerInvariant()] -ne 'Enabled')
                    {
                        Write-Information 'Registering Arc for servers.'
                        Write-EventLog -LogName Application -Source 'HCI Registration' -EventId 9002 -EntryType 'Information' -Message 'Initiating Arc For Servers registration'
                        Enable-AzureStackHCIArcIntegration -AgentInstallerWebLink $AgentInstaller_WebLink -AgentInstallerName $AgentInstaller_Name -AgentInstallerLogFile $AgentInstaller_LogFile -AgentExecutablePath $AgentExecutable_Path
                        Sync-AzureStackHCI
                        Write-EventLog -LogName Application -Source 'HCI Registration' -EventId 9003 -EntryType 'Information' -Message 'Completed Arc For Servers registration'
                    }
                    else
                    {
                        Write-Information 'Node is already registered.'
                    }
                }
                else
                {
                    # New node added case.
                    Write-Information 'Registering Arc for servers.'
                    Write-EventLog -LogName Application -Source 'HCI Registration' -EventId 9002 -EntryType 'Information' -Message 'Initiating Arc For Servers registration'
                    Enable-AzureStackHCIArcIntegration -AgentInstallerWebLink $AgentInstaller_WebLink -AgentInstallerName $AgentInstaller_Name -AgentInstallerLogFile $AgentInstaller_LogFile -AgentExecutablePath $AgentExecutable_Path
                    Sync-AzureStackHCI
                    Write-EventLog -LogName Application -Source 'HCI Registration' -EventId 9003 -EntryType 'Information' -Message 'Completed Arc For Servers registration'
                }
            }
            else
            {
                Write-Information ('Cluster Arc status is not enabled. ClusterArcStatus:' + $arcStatus.ClusterArcStatus.ToString())
            }
        }
        catch
        {
            Write-Error -Exception $_.Exception -Category OperationStopped
            # Get script line number, offset and Command that resulted in exception. Write-ErrorLog with the exception above does not write this info.
            $positionMessage = $_.InvocationInfo.PositionMessage
            Write-EventLog -LogName Application -Source "HCI Registration" -EventId 9116 -EntryType "Warning" -Message "Failed Arc For Servers registration: $positionMessage"
            Write-Error ('Exception occurred in RegisterArcScript : ' + $positionMessage) -Category OperationStopped
        }
        finally
        {
            try{ Stop-Transcript } catch {}
        }
    }
    Remove-PSSession -Session $session
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Temporary workaround for a bug in the May 2022 KVA module. This will get removed in a future update.
#>
function ModifyKvaModule
{
    $psm1File = (Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules" -Filter "kva.psm1" -Recurse).FullName

    $oldCode = '$tmpsecret = $tmp.Contexts.psobject.Members.Value[0].Account.ExtendedProperties.ServicePrincipalSecret'
    $newCode = '
    #################### BEGIN NEW CODE ####################
    $tmpsecret = $null
                
    for ($i = 0; $i -lt ($tmp.Contexts.psobject.Members.Value).Count; $i++) 
    {                    
        if ($tmp.Contexts.psobject.Members.Value[$i].Account.Id -eq $azContext.Account.Id)
        {
            $tmpsecret = $tmp.Contexts.psobject.Members.Value[$i].Account.ExtendedProperties.ServicePrincipalSecret
        }   
    }
    ####################  END NEW CODE  ####################'
    
    $findStr = [Regex]::Escape($oldCode)
    
    (Get-Content -Path $psm1File -Raw) -replace $findStr,$newCode | Set-Content -Path $psm1File

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Install AKSHCI and create a new workload cluster. The defaults here are scoped for a 64GB machine, 
    but can be changed if you have more capacity. Might make these variables in the future.
#>
function InstallAksHci
{
    # New PSSession to avoid module conflicts
    $session = New-PSSession -EnableNetworkAccess
    Invoke-Command -Session $session -ScriptBlock `
    {
        $spnSecStr = ConvertTo-SecureString -String $using:spnClientSecret -AsPlainText -Force
        $spnCredObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $using:spnClientId, $spnSecStr
        Connect-AzAccount -TenantId $using:spnTenantId -Subscription $using:subscriptionId -Credential $spnCredObj -Scope Process -ServicePrincipal

        # Need all 3 modules loaded for later
        Import-Module -Name 'AksHci'
        Import-Module -Name 'Moc'
        Import-Module -Name 'Kva'

        Initialize-AksHciNode

        # Dynamically discover existing settings. Saves you from having to manually enter data.
        $dnsServer = (Get-DnsClientServerAddress -InterfaceAlias "vEthernet (HCI-Uplink)" -AddressFamily IPv4).ServerAddresses[0]
        $defaultGw = (Get-NetRoute "0.0.0.0/0")[0].NextHop 
        
        $vNet = New-AksHciNetworkSetting `
            -name arcboxvnet `
            -vSwitchName "HCI-Uplink" `
            -k8sNodeIpPoolStart $using:aksNodeIpPoolStart `
            -k8sNodeIpPoolEnd $using:aksNodeIpPoolEnd `
            -vipPoolStart $using:aksVipPoolStart `
            -vipPoolEnd $using:aksVipPoolEnd `
            -ipAddressPrefix $using:cidrNetworkId `
            -gateway $defaultGw `
            -dnsServers $dnsServer `
            -Vlanid $aksvlanid 

        Set-AksHciConfig `
            -imageDir "C:\ClusterStorage\Volume01\Images" `
            -workingDir "C:\ClusterStorage\Volume01\ImageStore" `
            -cloudConfigLocation "C:\ClusterStorage\Volume01\Config" `
            -clusterRoleName $using:akscloudAgentName `
            -vnet $vNet `
            -cloudservicecidr $using:aksCloudIpCidr
        
        # Change some internal settings so this configuration will work as expected without DNS
        Set-MocConfigValue -Name "cloudFqdn" -Value $using:aksCloudAgentIp
        Set-KvaConfig -kvaName 'arcbox-aks-control' -vnet $vNet

        $armAccessToken = Get-AzAccessToken
        $graphAccessToken = Get-AzAccessToken -ResourceTypeName 'AadGraph'

        Set-AksHciRegistration `
            -subscriptionId $using:subscriptionId `
            -resourceGroupName $using:resourceGroup `
            -Region $using:azureLocation `
            -ArmAccessToken $armAccessToken.Token `
            -GraphAccessToken $graphAccessToken.Token `
            -AccountId $armAccessToken.UserId `
            -TenantId $using:spnTenantId `
            -Credential $spnCredObj

        # Install the AKS HCI controller itself
        Install-AksHci

        # Create settings for workload cluster. No load balancer to save resources.
        $lbConfig=New-AksHciLoadBalancerSetting -name "workloadLb" -loadBalancerSku "none"
    
        New-AksHciCluster `
            -name $using:aksWorkloadCluster `
            -controlPlaneVmSize 'Standard_K8S3_v1' `
            -loadBalancerSettings $lbConfig `
            -nodePoolName 'linuxnodepool' `
            -nodeVmSize $using:aksWorkerNodeVmSize `
            -nodeCount 4 `
            -primaryNetworkPlugin 'flannel' `
            -kubernetesVersion (Get-KvaConfig).kvaK8sVersion `
            -enableMonitoring 
    
        # Get a kubeconfig file for the newly created cluster, so kubectl will work as expected
        Get-AksHciCredential -Name $using:aksWorkloadCluster -Confirm:$false
    
        # Arc connect the new workload cluster
        Enable-AksHciArcConnection `
            -subscriptionId $using:subscriptionId `
            -resourceGroup $using:resourceGroup `
            -name $using:aksWorkloadCluster `
            -tenantId $using:spnTenantId `
            -credential $spnCredObj `
            -location $using:azureLocation
    
    }
    Remove-PSSession -Session $session
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Create a service bearer token so you can browse resources in the portal.
#>
function GenerateAksBearerToken
{
    kubectl create serviceaccount admin-user
    kubectl create clusterrolebinding admin-user-binding --clusterrole cluster-admin --serviceaccount default:admin-user
    $secretName = (kubectl get serviceaccount admin-user -o jsonpath='{$.secrets[0].name}')
    $secret = (kubectl get secret $secretName -o jsonpath='{$.data.token}')
    $token = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($secret))
    $token | Out-File -FilePath '.\ArcServiceToken.txt' -Encoding utf8 -Force

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    We now need to enable some features on the Arc-connected workload cluster to enable later scenarios
#>
function EnableArcK8sFeatures
{
    az login `
        --service-principal `
        --username $Env:spnClientId `
        --password $Env:spnClientSecret `
        --tenant $Env:spnTenantId
    if ($? -eq $false) 
    {
        Write-Error "Error logging into az cli."
        exit
    }

    az extension add --name connectedk8s

    az connectedk8s enable-features `
        --name $aksWorkloadCluster `
        --resource-group $resourceGroup `
        --custom-locations-oid '0ed99c2c-ca82-42c4-b00b-824d65e76ed1' `
        --features 'cluster-connect' 'custom-locations' `
        --verbose
    if ($? -eq $false) 
    {
        Write-Error "Error enabling Connected K8s features."
        exit
    }

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Install the Arc Data Services extension into the cluster
#>
function AddArcK8sExtensions
{
    az extension add --name k8s-extension

    az k8s-extension create `
        --cluster-name $aksWorkloadCluster `
        --resource-group $resourceGroup `
        --name 'arc-data-services' `
        --cluster-type 'connectedClusters' `
        --extension-type 'microsoft.arcdataservices' `
        --auto-upgrade 'true' `
        --scope 'cluster' `
        --release-namespace 'arc' `
        --config 'Microsoft.CustomLocation.ServiceAccount=sa-arc-bootstrapper' `
        --verbose
        if ($? -eq $false) 
    {
        Write-Error "Error creating Arc extensions in workload cluster."
        exit
    }

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Now that the extension is installed, we can create a Custom Location (cl) in Azure to use as a deployment target
#>
function CreateArcCustomLocation
{
    $session = New-PSSession -EnableNetworkAccess
    Invoke-Command -Session $session -ScriptBlock `
    {
        $spnSecStr = ConvertTo-SecureString -String $using:spnClientSecret -AsPlainText -Force
        $spnCredObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $using:spnClientId, $spnSecStr
        Connect-AzAccount -TenantId $using:spnTenantId -Subscription $using:subscriptionId -Credential $spnCredObj -Scope Process -ServicePrincipal

        $managedId = (Get-AzKubernetesExtension -clusterName $using:aksWorkloadCluster -ClusterType ConnectedClusters -ResourceGroupName $using:resourceGroup -Name 'arc-data-services').IdentityPrincipalId
        $roleScope = "/subscriptions/$using:subscriptionId/resourceGroups/$using:resourceGroup"

        New-AzRoleAssignment -ObjectId $managedId -RoleDefinitionName "Contributor" -Scope $roleScope
        New-AzRoleAssignment -ObjectId $managedId -RoleDefinitionName "Monitoring Metrics Publisher" -Scope $roleScope

        $arcHostResourceId = (Get-AzConnectedKubernetes -clusterName $using:aksWorkloadCluster -ResourceGroupName $using:resourceGroup).Id
        $arcClusterExtensionId = (Get-AzKubernetesExtension -clusterName $using:aksWorkloadCluster -ClusterType ConnectedClusters -ResourceGroupName $using:resourceGroup -Name 'arc-data-services').id

        New-AzCustomLocation `
            -Name 'jumpstart-cl' `
            -ResourceGroupName $using:resourceGroup `
            -Namespace 'arc' `
            -HostResourceId $arcHostResourceId `
            -ClusterExtensionId $arcClusterExtensionId `
            -Location $using:azureLocation
    }
    Remove-PSSession -Session $session
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Create the Arc data controller on our kube workload cluster.
#>
function CreateArcDataController
{
    az extension add --name arcdata

    az arcdata dc create `
        --name 'jumpstart-dc' `
        --resource-group $resourceGroup `
        --location $azureLocation `
        --connectivity-mode 'direct' `
        --profile-name 'azure-arc-aks-hci' `
        --auto-upload-logs 'true' `
        --auto-upload-metrics 'true' `
        --custom-location 'jumpstart-cl' `
        --storage-class 'default'
    if ($? -eq $false) 
    {
        Write-Error "Error creating Arc Data Controller."
        exit
    }

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
<#
    Set things back to the way they were. Don't want the script auto-running any longer.
#>
function DisableAutorun
{
    # Re-enable SConfig
    $ErrorActionPreference = 'SilentlyContinue'
    Set-SConfig -AutoLaunch $true

    # Stop the script from auto-launching
    Remove-Item -Path "$PSHOME\Profile.ps1" -Force -Confirm:$false

    # Disable autologon
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Remove-ItemProperty $RegistryPath 'AutoAdminLogon'  -Force
    Remove-ItemProperty $RegistryPath 'DefaultUsername' -Force
    Remove-ItemProperty $RegistryPath 'DefaultPassword' -Force

    $startLog = Select-String -Path $logfile -Pattern "ONENODESTART" -SimpleMatch
    $startTicks = [Int64](($startLog.Line).Split())[1]
    $startTime = [Datetime]$startTicks
    $runTime = ((Get-Date)-$startTime)
    $hr = $runTime.Hours
    $min = $runTime.Minutes
    $sec = $runTime.Seconds

    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Total runtime was" $hr"h" $min"m" $sec"s" -ForegroundColor DarkGreen


    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>

# Main execution begins here

$orginalErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Inquire"

$logFile = ('.\ExecutionTranscript.log')
Start-Transcript -Path $logFile -Append

try 
{
    Initialize-Variables
    $progressLog = Get-Content -Path '.\progress.log'

    $currentStepName = 'Init'
    $currentStepIndex = 0

    do 
    {
        if ($progressLog[$currentStepIndex].Contains("Pending"))
        {
            $currentStepName = ($progressLog[$currentStepIndex].Split())[0]
            Invoke-Expression -Command $currentStepName
        }
        $currentStepIndex++
        $progressLog = Get-Content -Path '.\progress.log' -Force
    }
    until ( $progressLog[$currentStepIndex] -eq "Done" )

}
finally 
{
    Stop-Transcript
    $ErrorActionPreference = $orginalErrorAction
}
