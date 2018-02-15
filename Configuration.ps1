# Install and Import AzureRM Module
Install-Module AzureRM -Scope CurrentUser -Force
Import-Module AzureRM -Force

# Install and Import the AWSPowerShell module
Install-Module -Name AWSPowerShell -Scope CurrentUser -Force
Import-Module AWSPowerShell -Force

# Install and Import Pester
Install-Module Pester -Scope CurrentUser -Force
Import-Module Pester -Force

$BaseDir = $PWD
if ($PSScriptRoot) { 
    $BaseDir = $PSScriptRoot
}

# Log in to Azure
Login-AzureRmAccount

$AWSCreds = Get-Credential -Message 'AWS Access Key and Secret Key'
# Settlings used by this project
$Settings = @{
    SrcDirectory = Join-Path $BaseDir src
    # Folder under which the Git repo will be cloned 
    GitDirectory = 'c:\Git'
    # Azure ResourceGroup Name
    ResourceGroupName             = 'PBnC'
    # See the -Location parameter of New-AzureRmResourceGroup for details
    ResourceGroupLocation         = "South Central US"
    # Options: Standard_LRS, Standard_GRS, Standard_RAGRS
    FunctionAppStorageAccountType = 'Standard_LRS'
    AwsAccessKey      = $AWSCreds.UserName
    AWSSecretKey      = $AWSCreds.GetNetworkCredential().Password
    AwsProfile        = 'Aws01'
    AwsRegion         = 'us-east-2'
    CCRepoName        = 'PBnC'
    CCRepoDescription = 'Peanut Butter and Chocolate'
}

# Create the Git Directory and change location to it
$Null = New-Item -ItemType Directory -Path $Settings.GitDirectory -Force -ErrorAction 'SilentlyContinue'
Push-Location $Settings.GitDirectory

# Hashtables used for storing results
$AzureAssets = @{}
$AWSAssets = @{}

# Create the PBnC Resource Group and add a Function App Deployment
$Params = @{
    Name     = $Settings.ResourceGroupName
    Location = $Settings.ResourceGroupLocation
}
$AzureAssets['ResourceGroup'] = New-AzureRmResourceGroup @Params
# This Template deploys the storage account, App Service account, and Function App.
$uri = 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-function-app-create-dynamic/azuredeploy.json'
$Params = @{
    TemplateUri        = $uri
    Name               = $AzureAssets['ResourceGroup'].ResourceGroupName
    ResourceGroupName  = $AzureAssets['ResourceGroup'].ResourceGroupName
    appName            = $AzureAssets['ResourceGroup'].ResourceGroupName
    storageAccountType = $Settings.FunctionAppStorageAccountType
}
$AzureAssets['Deployment'] = New-AzureRmResourceGroupDeployment @Params -ErrorVariable 'DeploymentErrors' 

# Enable Local Git based deployment on the Web App
$Params = @{
    PropertyObject    = @{
        scmType = "LocalGit"
    }
    ResourceGroupName = $Settings.ResourceGroupName 
    ResourceType      = 'Microsoft.Web/sites/config'
    ResourceName      = '{0}/web' -f $Settings.ResourceGroupName
    ApiVersion        = '2015-08-01'
}
$AzureAssets['WebAppProperties'] = Set-AzureRmResource @Params -Force

# Validate that the deployment was successful
Describe "Deployment of '$($Settings.ResourceGroupName)' Azure Function App" {
    It "Was Successful." {
        $DeploymentErrors.Count | Should -Be 0
        $AzureAssets['Deployment'].ProvisioningState | Should -BeExactly 'Succeeded'
    }
    It "Has a Storage Account." {
        $AzureAssets['Storage'] = Get-AzureRmStorageAccount -ResourceGroupName $AzureAssets['ResourceGroup'].ResourceGroupName

        $AzureAssets['Storage'].ProvisioningState | Should -BeExactly 'Succeeded'
    }
    It "Has an App Service Plan." {
        $AzureAssets['AppService'] = Get-AzureRmAppServicePlan -ResourceGroupName $AzureAssets['ResourceGroup'].ResourceGroupName

        $AzureAssets['AppService'].Status | Should -BeExactly 'Ready'
        $AzureAssets['AppService'].NumberOfSites | Should -Be 1
    }
    It "Has a Web App." {
        $AzureAssets['WebbApps'] = Get-AzureRmWebApp -ResourceGroupName $AzureAssets['ResourceGroup'].ResourceGroupName

        $AzureAssets['WebbApps'].Count | Should -Be 1
        $AzureAssets['WebbApps'][0].State | Should -BeExactly 'Running'
        $AzureAssets['WebbApps'][0].SiteName | Should -Be $AzureAssets['ResourceGroup'].ResourceGroupName
        $AzureAssets['WebbApps'][0].ServerFarmId | Should -Be $AzureAssets['AppService'].Id
    }
    It "Has Local Git Deployment enabled." {
        $AzureAssets['WebAppProperties'].Properties.scmType | Should -BeExactly 'LocalGit'
    }
}

# Grab the PublishProfile for the Web App. This gives us the deployment username and password
$AzureAssets['WebAppPublishingProfile'] = [xml](Get-AzureRmWebAppPublishingProfile -WebApp $AzureAssets['WebbApps'][0])
$AzureAssets['WebAppUserName'] = $AzureAssets['WebAppPublishingProfile'].publishData.publishProfile[0].userName
$AzureAssets['WebAppUserPwd'] = $AzureAssets['WebAppPublishingProfile'].publishData.publishProfile[0].userPWD
$AzureAssets['WebAppDeployUrl'] = 'https://{0}:{1}@{2}.scm.azurewebsites.net:443/deploy' -f @(
    [uri]::EscapeUriString($AzureAssets.WebAppUserName)
    $AzureAssets.WebAppUserPwd
    $AzureAssets.ResourceGroup.ResourceGroupName
)

# Create a credential profile
Set-AWSCredential -StoreAs $Settings.AwsProfile -AccessKey $Settings.AwsAccessKey -SecretKey $Settings.AWSSecretKey
Initialize-AWSDefaultConfiguration -ProfileName $Settings.AwsProfile -Region $Settings.AwsRegion 

$Params = @{
    RepositoryName        = $Settings.CCRepoName
    RepositoryDescription = $Settings.CCRepoDescription
}
$AWSAssets['CCRepo'] = New-CCRepository @Params -ErrorVariable 'CodeCommitRepoErrors'

Describe "Deployment of '$($Settings.CCRepoName)' AWS CodeCommit Repo" {
    It "Was Successful." {
        $ccrepo = Get-CCRepository -RepositoryName $Settings.CCRepoName

        $ccrepo.RepositoryName | Should -BeExactly $Settings.CCRepoName
        $ccrepo.RepositoryDescription | Should -BeExactly $Settings.CCRepoDescription
    }
}

# Copy the Sample function app, commit the changes and push to AWS CodeCommit
git clone $AWSAssets.CCRepo.CloneUrlSsh
Push-Location $Settings.ResourceGroupName
Copy-Item -Recurse ('{0}\*' -f $Settings.SrcDirectory) -Destination .
git add -A
git commit -m 'Add Example Function'
git push origin master



##### Diagnostics and Cleanup
$null = Start-AzureRmWebApp -WebApp $AzureAssets['WebbApps'][0]

Remove-AzureRmResourceGroup -Name $Settings.ResourceGroupName -Force
Remove-CCRepository -RepositoryName $Settings.CCRepoName -Force
Pop-Location; Pop-Location
Remove-Item -force -Recurse -confirm:$false $Settings.GitDirectory
Remove-Item -force -Recurse $Settings.ResourceGroupName