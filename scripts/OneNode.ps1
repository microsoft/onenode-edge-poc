[CmdletBinding()] param (
    [Parameter()]
    [String]$ConfigFile='./config.txt',
    [Switch]$ResetCluster
)
<#---------------------------------------------------------------------------------------------------------------#>
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
Function Update-Progress 
{
    $progressLog[$currentStepIndex] = "$currentStepName = Completed"
    $progressLog | Out-File -FilePath '.\progress.log' -Encoding utf8 -Force
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Completed Step:"(($progressLog[$currentStepIndex]).Split())[0] -ForegroundColor DarkGreen
    Write-Host "Next Step:"(($progressLog[$currentStepIndex+1]).Split())[0] -ForegroundColor DarkGreen

}
<#---------------------------------------------------------------------------------------------------------------#>
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
function Connect-ArcBoxSpn 
{

    $spnSecStr = ConvertTo-SecureString -String $env:spnClientSecret -AsPlainText -Force
    $spnCredObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:spnClientId, $spnSecStr

    # Sign in to Az PowerShell with the SPN in process-scope only. Avoids clobbering the users existing login
    Connect-AzAccount -TenantId $spnTenantId -Subscription $subscriptionId -Credential $spnCredObj -Scope Process -ServicePrincipal

}
<#---------------------------------------------------------------------------------------------------------------#>
function Get-NetworkPrefix {
    param (
        [IPAddress]$ip,
        [Int32]$prefix
    )
    $mask = [IPAddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $prefix))-1)
    return [IPAddress]($ip.Address -band $mask.Address)
}
<#---------------------------------------------------------------------------------------------------------------#>
function EnableAutorun 
{
    # Record start time
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
function AzBootstrap
{
    Install-PackageProvider -Name "NuGet" -MinimumVersion 2.8.5.201 -ForceBootstrap -Force -Confirm:$false
    Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted" 
    Install-Module -Name "PowershellGet" -Confirm:$false -SkipPublisherCheck -Force
    Install-Module -Name "Az.Resources"
    Install-Module -Name "Az.Accounts"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function CreateArcBoxSpn
{
    # Authorize this system to run commands against Azure
    Connect-AzAccount `
        -Subscription $subscriptionId `
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
function AssignSpnRoles
{
    # Assign required roles
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Security admin" 
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Security reader"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Monitoring Metrics Publisher"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "User Access Administrator"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Azure Connected Machine Onboarding"
    New-AzRoleAssignment -ApplicationId $spnClientId -RoleDefinitionName "Azure Connected Machine Resource Administrator"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
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
function CreateResourceGroup
{
    New-AzResourceGroup `
        -Name $resourceGroup `
        -Location $azureLocation `
        -Tag @{CreatedBy="OneNodeScript"}

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function InstallAzModules
{
    Install-Module -Name "Az.KubernetesConfiguration"
    Install-Module -Name "Az.CustomLocation"
    Install-Module -Name "Az.ConnectedKubernetes"
    Install-Module -Name "Az.OperationalInsights"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
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
function InstallAzCli
{
    # Fetch Azure CLI for Arc operations
    $azCliUri = "https://aka.ms/installazurecliwindows"
    $azCliPackage = "./azure-cli.msi"
    Import-Module -Name 'BitsTransfer'

    Start-BitsTransfer -Source $azCliUri -Destination $azCliPackage

    # Write-Warning "Azure CLI is installing in the background. This may take several minutes..."
    Start-Process msiexec.exe -Wait -ArgumentList '/I azure-cli.msi /passive'

    Set-Env -Name Path -Value "$env:Path;C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin;C:\Program Files\AksHci"
    az extension add --name arcdata
    az extension add --name connectedk8s
    az extension add --name k8s-extension

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
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

    Set-Item "WSMan:\localhost\Client\TrustedHosts" -Value '*' -Confirm:$false -Force
    Rename-Computer -NewName $nodeName

    Update-Progress
    Restart-Computer -Force
}
<#---------------------------------------------------------------------------------------------------------------#>
function CreateVmSwitch
{
    # Get all IPv4 addresses on this system
    $ipList = Get-NetIPAddress -AddressFamily IPv4

    # Iterate over all of them until you find the first one that's on the same network
    foreach ($ip in $ipList) 
    {
        $nicNetId = Get-NetworkPrefix -ip $ip.IPAddress -prefix $ip.PrefixLength
        $cluNetId = Get-NetworkPrefix -ip $hciClusterIp -prefix $ip.PrefixLength

        if ($nicNetId -eq $cluNetId) 
        {
            $global:cidrNetworkId = "$nicNetId/" + $ip.PrefixLength
            Update-ScriptConfig -varName "cidrNetworkId" -varValue $cidrNetworkId

            $global:aksCloudIpCidr = "$aksCloudAgentIp/" + $ip.PrefixLength
            Update-ScriptConfig -varName "aksCloudIpCidr" -varValue $aksCloudIpCidr

            New-VMSwitch `
                -Name "HCI-Uplink" `
                -EnableEmbeddedTeaming $true `
                -AllowManagementOS $true `
                -MinimumBandwidthMode 'Weight' `
                -NetAdapterName (Get-NetAdapter -InterfaceIndex $ip.ifIndex).Name
            break 
        }
        else 
        {
            Write-Warning "Could not find a network adapter on the same network as cluster network. Check your config file settings and try again"
            exit
        }
    }           
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function UpdateHostsFile 
{

    # Write out the hosts entries for the node and cluster
    $hciNodeIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "vEthernet (HCI-Uplink)").IPAddress

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
<#---------------------------------------------------------------------------------------------------------------#>
function CreateCluster
{
    # Create the cluster   
    New-Cluster `
        -Name $hciClusterName `
        -Node $nodeName `
        -StaticAddress $hciClusterIp `
        -AdministrativeAccessPoint 'DNS' `
        -NoStorage

    Update-Progress
}

function EnableS2D 
{
    # Clear out storage devices
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
function ModifyAzStackHciModule
{
    # Install cur
    Install-Module "Az.StackHCI" -Force
    $psm1File = (Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules" -Filter "Az.StackHCI.psm1" -Recurse).FullName

    $replaceStr = [Regex]::Escape(' + "." + $ClusterDNSSuffix')
    (Get-Content -Path $psm1File -Raw) -replace $replaceStr,'' | Set-Content -Path $psm1File

    $replaceStr = [Regex]::Escape('$ClusterScheduledTaskWaitTimeMinutes = 15')
    (Get-Content -Path $psm1File -Raw) -replace $replaceStr,'$ClusterScheduledTaskWaitTimeMinutes = 0' | Set-Content -Path $psm1File
    Import-Module -Name "Az.StackHCI"

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function RegisterHciCluster
{
    Connect-ArcBoxSpn

    $armAccessToken = Get-AzAccessToken
    $graphAccessToken = Get-AzAccessToken -ResourceTypeName 'AadGraph'

    Register-AzStackHCI `
        -SubscriptionId $subscriptionId `
        -Region $azureLocation `
        -ResourceName $hciClusterName `
        -ResourceGroupName $resourceGroup `
        -ArmAccessToken $armAccessToken.Token `
        -GraphAccessToken $graphAccessToken.Token `
        -AccountId $armAccessToken.UserId `
        -ArcServerResourceGroupName $hciArcServersRg `
        -EnableAzureArcServer:$true `
        -Tag @{CreatedBy="OneNodeScript"}
        
    Update-Progress

}
<#---------------------------------------------------------------------------------------------------------------#>
function RunArcAgentTaskManually
{
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

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function AksHciPrep
{
    Install-Module -Name "AksHci" -Repository "PSGallery" -AcceptLicense -Confirm:$false -Force

    Import-Module -Name 'AksHci'
    Initialize-AksHciNode

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function InstallAksHci
{
    $dnsServer = (Get-DnsClientServerAddress -InterfaceAlias "vEthernet (HCI-Uplink)" -AddressFamily IPv4).ServerAddresses[0]
    $defaultGw = (Get-NetRoute "0.0.0.0/0")[0].NextHop 
    
    $vNet = New-AksHciNetworkSetting `
        -name arcboxvnet `
        -vSwitchName "HCI-Uplink" `
        -k8sNodeIpPoolStart $aksNodeIpPoolStart `
        -k8sNodeIpPoolEnd $aksNodeIpPoolEnd `
        -vipPoolStart $aksVipPoolStart `
        -vipPoolEnd $aksVipPoolEnd `
        -ipAddressPrefix $cidrNetworkId `
        -gateway $defaultGw `
        -dnsServers $dnsServer

    Set-AksHciConfig `
        -imageDir "C:\ClusterStorage\Volume01\Images" `
        -workingDir "C:\ClusterStorage\Volume01\ImageStore" `
        -cloudConfigLocation "C:\ClusterStorage\Volume01\Config" `
        -clusterRoleName $akscloudAgentName `
        -vnet $vNet `
        -cloudservicecidr $aksCloudIpCidr

    Import-Module -Name 'Moc'
    Import-Module -Name 'Kva'
    
    Set-MocConfigValue -Name "cloudFqdn" -Value $aksCloudAgentIp
    Set-KvaConfig -kvaName 'arcbox-aks-control' -vnet $vNet

    $spnPwd = ConvertTo-SecureString $env:spnClientSecret -AsPlainText -Force
    $spnCredObj = New-Object System.Management.Automation.PSCredential ($env:spnClientId, $spnPwd)

    Connect-ArcBoxSpn
    $armAccessToken = Get-AzAccessToken
    $graphAccessToken = Get-AzAccessToken -ResourceTypeName 'AadGraph'

    Set-AksHciRegistration `
        -subscriptionId $subscriptionId `
        -resourceGroupName $resourceGroup `
        -Region $azureLocation `
        -ArmAccessToken $armAccessToken.Token `
        -GraphAccessToken $graphAccessToken.Token `
        -AccountId $armAccessToken.UserId `
        -TenantId $spnTenantId `
        -Credential $spnCredObj

    Install-AksHci
    
    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function CreateWorkloadCluster 
{
    $spnPwd = ConvertTo-SecureString $env:spnClientSecret -AsPlainText -Force
    $spnCredObj = New-Object System.Management.Automation.PSCredential ($env:spnClientId, $spnPwd)

    $lbConfig=New-AksHciLoadBalancerSetting -name "workloadLb" -loadBalancerSku "none"
    
    New-AksHciCluster `
        -name $aksWorkloadCluster `
        -controlPlaneVmSize 'Standard_K8S3_v1' `
        -loadBalancerSettings $lbConfig `
        -nodePoolName 'linuxnodepool' `
        -nodeVmSize $aksWorkerNodeVmSize `
        -nodeCount 4 `
        -primaryNetworkPlugin 'flannel' `
        -kubernetesVersion (Get-KvaConfig).kvaK8sVersion `
        -enableMonitoring 

    Get-AksHciCredential -Name $aksWorkloadCluster -Confirm:$false

    Enable-AksHciArcConnection `
        -subscriptionId $subscriptionId `
        -resourceGroup $resourceGroup `
        -name $aksWorkloadCluster `
        -tenantId $spnTenantId `
        -credential $spnCredObj `
        -location $azureLocation

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
function GenerateAksBearerToken
{
    # Create a service token so you can browse resources in the portal
    kubectl create serviceaccount admin-user
    kubectl create clusterrolebinding admin-user-binding --clusterrole cluster-admin --serviceaccount default:admin-user
    $secretName = (kubectl get serviceaccount admin-user -o jsonpath='{$.secrets[0].name}')
    $secret = (kubectl get secret $secretName -o jsonpath='{$.data.token}')
    $token = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($secret))
    $token | Out-File -FilePath '.\ArcServiceToken.txt' -Encoding utf8 -Force

    Update-Progress
}
<#---------------------------------------------------------------------------------------------------------------#>
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
function AddArcK8sExtensions
{
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
function CreateArcCustomLocation
{
    $managedId = (Get-AzKubernetesExtension -clusterName $aksWorkloadCluster -ClusterType ConnectedClusters -ResourceGroupName $resourceGroup -Name 'arc-data-services').IdentityPrincipalId
    $roleScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup"

    New-AzRoleAssignment -ObjectId $managedId -RoleDefinitionName "Contributor" -Scope $roleScope
    New-AzRoleAssignment -ObjectId $managedId -RoleDefinitionName "Monitoring Metrics Publisher" -Scope $roleScope

    $arcHostResourceId = (Get-AzConnectedKubernetes -clusterName $aksWorkloadCluster -ResourceGroupName $resourceGroup).Id
    $arcClusterExtensionId = (Get-AzKubernetesExtension -clusterName $aksWorkloadCluster -ClusterType ConnectedClusters -ResourceGroupName $resourceGroup -Name 'arc-data-services').id

    New-AzCustomLocation `
        -Name 'jumpstart-cl' `
        -ResourceGroupName $resourceGroup `
        -Namespace 'arc' `
        -HostResourceId $arcHostResourceId `
        -ClusterExtensionId $arcClusterExtensionId `
        -Location $azureLocation

    Update-Progress
}

function CreateArcDataController
{
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
