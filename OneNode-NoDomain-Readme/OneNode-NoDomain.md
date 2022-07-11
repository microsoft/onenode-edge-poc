# Azure Stack HCI, Single Node Deployment Guide # 

This guide describes how to deploy Azure Stack HCI, version 21H2 on a Single Node with no domain requirment via the included Powershell Script and Configuration file.

The target audience for this guide is IT administrators familiar with the existing Azure Stack HCI solution or Developers who wish to have a small on premises environment.

**Important**  
Please review the terms of use for the preview and sign up before you deploy this solution.

## Prerequisites ##
Here you will find the software, hardware, and networking prerequisites to deploy Azure Stack HCI, version 21H2: 

### Software requirements ###
Before you begin, make sure that the following software requirement is met:

|Component | Description |  
--| --|
|Operating System |You must install and set up the Azure Stack HCI, version 21H2 OS to boot using the instructions in this [link.](https://docs.microsoft.com/en-us/azure-stack/hci/deploy/operating-system)|  |

### Hardware requirements ### 
Before you begin, make sure that the physical hardware used to deploy the solution meets the following requirements:

|Component | Minimum |  
--| --|
|CPU | A 64-bit Intel Nehalem grade or AMD EPYC or later compatible processor with second-level address translation (SLAT). |
|Memory | A minimum of 32 GB RAM.|
|Host network adapters|At least one network adapter listed in the Windows Server Catalog.|
|BIOS|Intel VT or AMD-V must be turned on.|
|Boot Drive| A minimum size of 128 GB size. |
|Data Drives|At least 1 disks with a minimum capacity of 500 GB(SSD or NVME). |
|TPM |TPM 2.0 hardware must be present and turned on. |
|Secure Boot | Secure boot must be present and enabled|



### Network requirements ###  

Before you begin, make sure that the physical network and the host network where the solution is deployed meet the requirements described in:

•	[Physical network requirements](https://docs.microsoft.com/azure-stack/hci/concepts/physical-network-requirements)

•	[Host network requirements](https://docs.microsoft.com/azure-stack/hci/concepts/host-network-requirements)

Note: Advanced settings within storage network configuration like iWarp or MTU changes are not supported in this release.

## Deploy Azure Stack HCI; Single Node ##

|Step # | Description|
--| --|
|Prerequisites|1. [Software Requirments]() 2.[Hardware requirments]() 3. [Network Requirments]() |
|Step 0| [Step 0](./OneNode-NoDomain.md/#step-0-pre-deployment-checklist) |
|Step 1|[Step 1](./OneNode-NoDomain.md/#step-1-install-the-operating-system)|| 
|Step 2|[Step 2](./OneNode-NoDomain.md/#step-2-set-up-the-deployment-tool)|
|Step 3|[Step 3](./OneNode-NoDomain.md/#step-3-run-the-onenode-script)|
|Step 3|[Step 4](./OneNode-NoDomain.md/#step-4-optional--deploy-windows-admin-center)|
|Step 3|[Step 5](./OneNode-NoDomain.md/#step-5-utilize-the-services-deployed)|


## Step-by-step deployment ##

### Step 0 Pre-Deployment Checklist ###
Use the following check list to gather this information ahead of the actual deployment of your Azure Stack HCI cluster. This information will be used to configure the single node and also prepare the Configuration Deployment File, which is named Config.txt. 

### Step 1: Install the Operating System ###

The first step in deploying Azure Stack HCI is to [download Azure Stack HCI](https://azure.microsoft.com/products/azure-stack/hci/hci-download/) and install the operating system on each server that you want to cluster. This article discusses different ways to deploy the operating system, and using Windows Admin Center to connect to the servers.

#### Determine hardware and network requirements

Microsoft recommends purchasing a validated Azure Stack HCI hardware/software solution from our partners. These solutions are designed, assembled, and validated against our reference architecture to ensure compatibility and reliability, so you get up and running quickly. Check that the systems, components, devices, and drivers you are using are certified for use with Azure Stack HCI. Visit the [Azure Stack HCI solutions](https://azure.microsoft.com/overview/azure-stack/hci) website for validated solutions.

At minimum, you need one server, a reliable high-bandwidth, low-latency network connection between servers, and SATA, SAS, NVMe, or persistent memory drives that are physically attached to just one server each. However, your hardware requirements may vary depending on the size and configuration of the cluster(s) you wish to deploy. To make sure your deployment is successful, review the Azure Stack HCI [system requirements](../concepts/system-requirements.md).

Before you deploy the Azure Stack HCI operating system:

- Plan your [physical network requirements](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/azure-stack/hci/concepts/physical-network-requirements.md) and [host network requirements](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/azure-stack/hci/concepts/host-network-requirements.md).
- Carefully [choose drives](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/azure-stack/hci/concepts/choose-drives.md) and [plan volumes](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/azure-stack/hci/concepts/plan-volumes.md) to meet your storage performance and capacity requirements.

For Azure Kubernetes Service on Azure Stack HCI and Windows Server requirements, see [AKS requirements on Azure Stack HCI](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/azure-stack/aks-hci/overview.md#what-you-need-to-get-started).

#### Gather information

To prepare for deployment, you'll need to take note of the server names, domain names*, and versions, and VLAN ID for your deployment. Gather the following details about your environment:

- **Server name:** Get familiar with your organization's naming policies for computers, files, paths, and other resources. If you need to provision several servers, each should have a unique name.
- **Domain name:** Get familiar with your organization's policies for domain naming and domain joining. You'll be joining the servers to your domain, and you'll need to specify the domain name.
- **Static IP addresses:** Azure Stack HCI requires static IP addresses for storage and workload (VM) traffic and doesn't support dynamic IP address assignment through DHCP for this high-speed network. You can use DHCP for the management network adapter unless you're using two in a team, in which case again you need to use static IPs. Consult your network administrator about the IP address you should use for each server in the cluster.
- **VLAN ID:** Note the VLAN ID to be used for the network adapters on the servers, if any. You should be able to obtain this from your network administrator.


    **Important**    
    This deployment script can operate in 2 Modes, Domain Required or No Domain Required. This is because of the nature of Single Node Azure Stack HCI, the technology will allow for a No Domain option. This is in now way a SUPPORTED operation mode for Azure Stack HCI and is NOT recomended for Production workloads. This is simply to support a quick development environment for testing Azure Stack HCI and it's features including Azure Kubernetes Solution on Azure Stack HCI, Ifrastructure as a Service, Azure Virtual Desktop on Azure Stack HCI (Currently in Preview) and more. Please use this deployment method only for Development and Concept Testing only.  
---
#### Prepare hardware for deployment

After you've acquired the server hardware for your Azure Stack HCI solution, it's time to rack and cable it. Use the following steps to prepare the server hardware for deployment of the operating system.

1. Rack all server nodes that you want to use in your server cluster.
1. Connect the server nodes to your network switches.
1. Configure the BIOS or the Unified Extensible Firmware Interface (UEFI) of your servers as recommended by your Azure Stack HCI hardware vendor to maximize performance and reliability.

> **Important**
>If you are installing Azure Stack HCI on to a Virtual Machine, please mount the ISO image to the Virtual Machine, and proceed to Boot to VHD (or VMDX, etc) and continue the installation process. 

#### Operating system deployment options

You can deploy the Azure Stack HCI operating system in the same ways that you're used to deploying other Microsoft operating systems:

- Server manufacturer pre-installation.
- Headless deployment using an answer file.
- System Center Virtual Machine Manager (VMM).
- Network deployment.
- Manual deployment by connecting either a keyboard and monitor directly to the server hardware in your datacenter, or by connecting a KVM hardware device to the server hardware.

##### Headless deployment

You can use an answer file to do a headless deployment of the operating system. The answer file uses an XML format to define configuration settings and values during an unattended installation of the operating system.

For this deployment option, you can use Windows System Image Manager to create an unattend.xml answer file to deploy the operating system on your servers. Windows System Image Manager creates your unattend answer file through a graphical tool with component sections to define the "answers" to the configuration questions, and then ensure the correct format and syntax in the file.
The Windows System Image Manager tool is available in the Windows Assessment and Deployment Kit (Windows ADK). To get started: [Download and install the Windows ADK](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/windows-hardware/get-started/adk-install).

##### System Center Virtual Machine Manager (VMM) deployment

You can use [System Center 2022](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/system-center) to deploy the Azure Stack HCI, version 21H2 operating system on bare-metal hardware, as well as to cluster and manage the servers. For more information about using VMM to do a bare-metal deployment of the operating system, see [Provision a Hyper-V host or cluster from bare metal computers](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/system-center/vmm/hyper-v-bare-metal).

> **IMPORTANT**
> You can't use Microsoft System Center Virtual Machine Manager 2019 to deploy or manage clusters running Azure Stack HCI, version 21H2. If you're using VMM 2019 to manage your Azure Stack HCI, version 20H2 cluster, don't attempt to upgrade the cluster to version 21H2 without first installing [System Center 2022](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/system-center).

##### Network deployment

Another option is to install the Azure Stack HCI operating system over the network using [Windows Deployment Services](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831764(v=ws.11)).

##### Manual deployment

To manually deploy the Azure Stack HCI operating system on the system drive of each server to be clustered, install the operating system via your preferred method, such as booting from a DVD or USB drive. Complete the installation process using the Server Configuration tool (Sconfig) to prepare the server or servers for clustering. To learn more about the tool, see [Configure a Server Core installation with Sconfig](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/windows-server/windows-server-2022/get-started/sconfig-on-ws2022).

To manually install the Azure Stack HCI operating system:

1. Start the Install Azure Stack HCI wizard on the system drive of the server where you want to install the operating system.
1. Choose the language to install or accept the default language settings, select **Next**, and then on next page of the wizard, select **Install now**.
![alt ext](./Media/azure-stack-hci-install-language.png "The language page of the Install Azure Stack HCI wizard")


1. On the Applicable notices and license terms page, review the license terms, select the **I accept the license terms** checkbox, and then select **Next**.
1. On the Which type of installation do you want? page, select **Custom: Install the newer version of Azure Stack HCI only (advanced)**.

    > **NOTE**
    > Upgrade installations are not supported in this release of the operating system.
![alt text](./Media/azure-stack-hci-install-which-type.png"The installation type option page of the Install Azure Stack HCI wizard.") 

1. On the Where do you want to install Azure Stack HCI? page, either confirm the drive location where you want to install the operating system or update it, and then select **Next**.

![alt text](./Media/azure-stack-hci-install-where.png "The drive location page of the Install Azure Stack HCI wizard.")

1. The Installing Azure Stack HCI page displays to show status on the process.

    ![alt text](./Media/azure-stack-hci-installing.png "The status page of the Install Azure Stack HCI wizard.")

    > **NOTE**
    > The installation process restarts the operating system twice to complete the process, and displays notices on starting services before opening an Administrator command prompt.

1. At the Administrator command prompt, select **Ok** to change the user's password before signing in to the operating system, and press Enter.

    ![alt text](./Media/azure-stack-hci-change-admin-password.png "The change password prompt.")


1. At the Enter new credential for Administrator prompt, enter a new password, enter it again to confirm it, and then press Enter.
1. At the Your password has been changed confirmation prompt, press Enter.

    ![alt text](./Media/azure-stack-hci-admin-password-changed.png "The changed password confirmation prompt")

Now you're ready to use the Server Configuration tool (Sconfig) to perform important tasks. To use Sconfig, log on to the server running the Azure Stack HCI operating system. This could be locally via a keyboard and monitor, or using a remote management (headless or BMC) controller, or Remote Desktop. The Sconfig tool opens automatically when you log on to the server.

![alt text](./Media/azure-stack-hci-sconfig-screen.png )

From the Welcome to Azure Stack HCI window (Sconfig tool), you can perform the following initial configuration tasks:

- Configure networking or confirm that the network was configured automatically using Dynamic Host Configuration Protocol (DHCP).
- Rename the server if the default automatically generated server name does not suit you.
- Join the server to an Active Directory domain.
- Add your domain user account or designated domain group to local administrators.
- Enable access to Windows Remote Management (WinRM) if you plan to manage the server from outside the local subnet and decided not to join domain yet. (The default Firewall rules allow management both from local subnet and from any subnet within your Active Directory domain services.)

For more detail, see [Server Configuration Tool (SConfig)](https://github.com/MicrosoftDocs/azure-stack-docs/blob/main/windows-server/administration/server-core/server-core-sconfig).

After configuring the operating system as needed with Sconfig on each server, you're ready to use the Cluster Creation wizard in Windows Admin Center to cluster the servers.

> **NOTE**
> If you're installing Azure Stack HCI on a single server, you must use PowerShell to create the cluster.




### Step 2: Set up the deployment tool ###
The Server will itself  act as a staging server (seed node)   during deployment of the cluster. In order to achieve this, you will need to copy over the OneNode Script and Config File to the staging server using whatever method you choose. 

Note: If you use a USB drive or any Removable Media, please disconnect the drives before running the Script, as it could erase the contents of any non-operating system disks during the Storage Spaces Direct Installation stages. 


Copy downloaded content from the GitHub Repop to any drive, recomended method is C:\temp or C:\Scripts
Confirm the Config.txt is available and confirm the Values
The deployment script requires the following parameters to be located in the Config.txt file:


|Parameters|Description|
|--|--|
|Jumpstart Scenerios||
|deployArcDataServices| Mark as True or False if you would like to deploy Azure Arc Data Services|
|deploySQLMI|Mark as True or False if you would like to deploy Azure SQL Managed Instance|
|deployPostgreSQL|Mark as True or False if you would like to deploy Azure PostgreSQL|
|deployAppService|Mark as True or False if you would like to deploy Azure Arc Application Services|
|deployFunction|Mark as True or False if you would like to deploy Azure Functions|
|deployAPIMgmt|Mark as True or False if you would like to deploy Azure API Management Services|
|deployLogicApp|Mark as True or False if you would like to deploy Azure Logic App Services|
|||
|Host Variables||
|AdminUserName| Please provide the Server Local Administrator Username|
|AdminPassword|Please provide the Server Local Administrator Password|
|NodeName| Please Provide the desired Server Node Name |
|||
|Azure Variables||
|spnDisplayName| Please Provide the Prefered Name for the Service Principal Account that will be created in your Azure Subscription|
|ResourceGroup| Please Provide the Pre-Created Azure Resource Group Name|
|SubscriptionID| Please Provide the Azure Subscription ID Number|
|TenantID|Please Provide the Azure Active Directory Tenant ID Number|
|AzureLocation| Please Provide the Prefered Azure Region|
|WorkspaceName|Please Provide the Prefered Azure Log Analytics Workspace Name to be created.|
|||
|HCI Variables||
|HCIClusterName|Please Provide the Desired HCI Cluster Name|
|HCINodeIP|Please Provide the IP Address to be used as the Node IP Address, this can not be the same as the Cluster IP supplied below, but should be in the same VNet as that.|
|HCIClusterIP|Please Provide the IP Address to be used as the Cluster IP Address, this can not be the same as the Node IP supplied above, but should be in the same VNet as that.|
|HCIArcServerRG| Please Provide the Prefered name of the Azure Resource Group that will be created for the HCI Registration Azure Resource to be created in.|
|||
|AKS Variables||
|AKSNodeIPPoolStart|You must specify a [Kubernetes node VM IP pool range](https://docs.microsoft.com/en-us/azure-stack/aks-hci/concepts-node-networking#kubernetes-node-vm-ip-pool).Please Provide the starting IP for this Range.|
|AKSNodeIPPoolEnd|Please Provide the Ending IP Address for this Range|
|AKSVIPPoolStart|A [Virtual IP (VIP) pool](https://docs.microsoft.com/en-us/azure-stack/aks-hci/concepts-node-networking#virtual-ip-pool) is set of IP addresses that are mandatory for any AKS on Azure Stack HCI. Please Provide the Starting IP Address for the VIP Pool|
|AKSVIPPoolEnd|Please provide the ending IP Address for this range.|
|AKSCloudAgentIP|A single instance of a highly available [cloud agent service](https://docs.microsoft.com/en-us/azure-stack/aks-hci/concepts-node-networking#microsoft-on-premises-cloud-service) deployed in the cluster. This agent runs on any one node in the Azure Stack HCI| Please provide the IP Address to be used for this service, it is advised that this be in the same vnet as the Node and Cluster IP Address.
|AKSCloudAgentName|Please provide the Cloud Agent Name|
|AKSWorkloadCluster|Please provide the name of the first workload cluster to be deployed|
|AKSWorkerNodeVMSize|Please provide Worker Node VM Size, Default is Standard_K8S3_v1 for 1 worker node = 6GB|
|||
|Arc Data Services Variables||
|ArcDSExtName|Please provide name for [Arc Data Services Extension](https://docs.microsoft.com/en-us/azure/azure-arc/data/create-data-controller-direct-cli?tabs=windows) Name|
|ArcDSNameSpace|Please provide name for Arc Data Services Namespace|
|AZData_Username|Please provide Arc Data Service Username|
|AZData_Password|Please provide Arc Data Service Password|
|Accept_EULA|Please Accept Arc Data Services EULA|

### Step 3: Run the OneNode Script
With the OneNode.PS1 and Config.txt file located on the node, and all PreRequisites completed, deployment can be started. In Powershell navigate to the directory that OneNode.ps1 was copied to. Run the following:

```Powershell
& .\OneNode.ps1
```

The Script will begin and run through all the steps neccesary to deploy your Single Node Azure Stack HCI Cluster without the need for Domain Membership. This process will include several restarts over the course of an couple of hours. After reboot the script will resume at next login, so be sure the monitor the progress. For your convience the Progress.log file has been created in the Script directory and will allow you to also track the sequential steps as they are happening. The Script is also Verbose so monitoring can be achieved in the PowerShell session. 

### Step 4: Optional- Deploy Windows Admin Center ###

#### Install Windows Admin Center

Windows Admin Center is a locally deployed, browser-based app for managing Azure Stack HCI. The simplest way to [install Windows Admin Center](/windows-server/manage/windows-admin-center/deploy/install) is on a local management PC (desktop mode), although you can also install it on a server (service mode).

If you install Windows Admin Center on a server, tasks that require CredSSP, such as cluster creation and installing updates and extensions, require using an account that's a member of the Gateway Administrators group on the Windows Admin Center server. For more information, see the first two sections of [Configure User Access Control and Permissions](/windows-server/manage/windows-admin-center/configure/user-access-control#gateway-access-role-definitions).

### Step 5: Utilize the Services deployed ###
#### Next Steps ####
Now that the Cluster has been deployed, the services that were enabled and deployed can be utilized. This includes:

|Service| Link to Get Started| 
--|--|
Azure Kubernetes Service|[Create a local Kubernetes cluster in the Azure Kubernetes Service host dashboard ](https://docs.microsoft.com/en-us/azure-stack/aks-hci/create-kubernetes-cluster#create-a-local-kubernetes-cluster-in-the-azure-kubernetes-service-host-dashboard)|
Virtual Machines|[Manage Virtual Machines from Windows Admin Center](https://docs.microsoft.com/en-us/azure-stack/hci/manage/vm#create-a-new-vm)|
Azure SQL MI|[Create Azure Arc-enabled SQL Managed Instance using Kubernetes tools](https://docs.microsoft.com/en-us/azure/azure-arc/data/create-sql-managed-instance-using-kubernetes-native-tools)|
Azure PostgreSQL|[Create a PostgreSQL Hyperscale server group using Kubernetes tools](https://docs.microsoft.com/en-us/azure/azure-arc/data/create-postgresql-hyperscale-server-group-kubernetes-native-tools)|
Azure Functions|[Set up an Azure Arc-enabled Kubernetes cluster to run App Service, Functions, and Logic Apps (Preview)](https://docs.microsoft.com/en-us/azure/app-service/manage-create-arc-environment?tabs=bash)|
Azure API Management|[Getting Started with Azure Arc enabled API Management](https://docs.microsoft.com/en-us/azure/api-management/how-to-deploy-self-hosted-gateway-kubernetes)|

You can begin Management of the Cluster in a number of ways:
1. [Azure Portal](https://portal.azure.com)
2. [Windows Admin Center](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/azure/manage-arc-hybrid-machines?toc=%2Fazure%2Fazure-arc%2Fservers%2Ftoc.json&bc=%2Fazure%2Fazure-arc%2Fservers%2Fbreadcrumb%2Ftoc.json)
3. Powershell


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.


Contributions & Legal
Contributing
This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact opencode@microsoft.com with any additional questions or comments.

Legal Notices
Microsoft and any contributors grant you a license to the Microsoft documentation and other content in this repository under the Creative Commons Attribution 4.0 International Public License, see the LICENSE file, and grant you a license to any code in the repository under the MIT License, see the LICENSE-CODE file.

Microsoft, Windows, Microsoft Azure and/or other Microsoft products and services referenced in the documentation may be either trademarks or registered trademarks of Microsoft in the United States and/or other countries. The licenses for this project do not grant you rights to use any Microsoft names, logos, or trademarks. Microsoft's general trademark guidelines can be found at http://go.microsoft.com/fwlink/?LinkID=254653.

Privacy information can be found at https://privacy.microsoft.com/en-us/

Microsoft and any contributors reserve all other rights, whether under their respective copyrights, patents, or trademarks, whether by implication, estoppel or otherwise.