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

$AWSCreds = Get-Credential -Message 'AWS Access Key and Secret Key'
# Settlings used by this project
$Settings = @{
    SrcDirectory                  = Join-Path $BaseDir src
    # Folder under which the Git repo will be cloned 
    GitDirectory                  = 'c:\Git'
    # Azure ResourceGroup Name
    ResourceGroupName             = 'PBnC'
    # See the -Location parameter of New-AzureRmResourceGroup for details
    ResourceGroupLocation         = "South Central US"
    # Options: Standard_LRS, Standard_GRS, Standard_RAGRS
    FunctionAppStorageAccountType = 'Standard_LRS'
    AwsAccessKey                  = $AWSCreds.UserName
    AWSSecretKey                  = $AWSCreds.GetNetworkCredential().Password
    AwsProfile                    = 'Aws01'
    AwsRegion                     = 'us-east-2'
    CCRepoName                    = 'PBnC'
    CCRepoDescription             = 'Peanut Butter and Chocolate'
    CCGitUser                     = 'PBnC-Git-User'
    CCGitUserPolicyName           = 'PBnC-Git-User-{0}' -f [Guid]::NewGuid()
}

# Hashtables used for storing results from commands
$AzureAssets = @{}
$AWSAssets = @{}


# Log in to Azure
$AzureAssets['AccountLogin'] = Login-AzureRmAccount

# Create AWS credential profile and set it as the default configuration
Set-AWSCredential -StoreAs $Settings.AwsProfile -AccessKey $Settings.AwsAccessKey -SecretKey $Settings.AWSSecretKey
Initialize-AWSDefaultConfiguration -ProfileName $Settings.AwsProfile -Region $Settings.AwsRegion 


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

# Create a new AWS IAM User required for CodeCommit Git Credentials
$Params = @{
    UserName = $Settings.CCGitUser
    Force = $true
}
$AWSAssets['IAMUser'] = New-IAMUser @Params

# Create the IAM policy document and set it for the user
$PolicyDocument = @"
{
  "Version": "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Action" : [
        "codecommit:GitPull"
      ],
      "Resource" : [
        "$($AWSAssets.CCRepo.Arn)"
      ]
    }
  ]
}
"@
$Params = @{
    PolicyDocument = $PolicyDocument
    PolicyName = $Settings.CCGitUserPolicyName
    userName = $AWSAssets.IAMUser.UserName
    force = $true
    PassThru = $true
}
$AWSAssets['IAMPolicy'] = Write-IAMUserPolicy @Params

Describe "AWS Git User" {
    It "Was successfully created" {
        $user = Get-IAMUser -UserName $Settings.CCGitUser
        $user.UserName | should -BeExactly $Settings.CCGitUser
    }
    It "Has a policy attached" {
        $policy = Get-IAMUserPolicy -PolicyName $Settings.CCGitUserPolicyName -UserName $Settings.CCGitUser
        $PolicyObj = [uri]::UnescapeDataString($policy.PolicyDocument) | ConvertFrom-Json
        
        $PolicyObj.Statement[0].Effect | should -BeExactly 'Allow'
        $PolicyObj.Statement[0].Action[0] | should -BeExactly 'codecommit:GitPull'
        $PolicyObj.Statement[0].Resource[0] | should -BeExactly $AWSAssets.CCRepo.Arn
    }
}

# At this point we need to use th AWS web console to generate 
$ConsoleUrl = 'https://console.aws.amazon.com/iam/home?region={0}#/users/{1}section=security_credentials' -f 
    $Settings.AwsRegion, $Settings.CCGitUser
Write-Host @"


Before continuing, you must generate HTTPS Git credentials for AWS CodeCommit for the $($Settings.CCGitUser) user.
Currently, this can only be done in the AWS web console.
You will need to use a web browser to login to the AWS console with an user that has IAM edit permissions.
Then navigate to 

    $ConsoleUrl

Once you generate the HTTPS Git credentials for AWS CodeCommit, enter the generated username and password.


"@
$AWSAssets['CCGitUserCredentials'] = Get-Credential -Message "HTTPS Git credentials for AWS CodeCommit"

# Create the Git Directory and change location to it
$Null = New-Item -ItemType Directory -Path $Settings.GitDirectory -Force -ErrorAction 'SilentlyContinue'
Push-Location $Settings.GitDirectory

# Clone the empty CodeCommit repository
git clone $AWSAssets.CCRepo.CloneUrlSsh
Push-Location $Settings.ResourceGroupName

# Add an empty host.json file. This will let us confirm the Azure Web App Deployment settings are working
'{}' | Set-Content 'host.json'
git add -A
git commit -m 'Initial Commit'
git push --force

Describe "Initial Git Commit" {
    It "Was successful" {
        $diffs = Get-CCDifferenceList -AfterCommitSpecifier "master" -RepositoryName $Settings.ResourceGroupName
        
        $diffs.count | Should -BeExactly 1
        $diffs[0].ChangeType | Should -BeExactly 'A'
        $diffs[0].AfterBlob.Path | Should -BeExactly 'host.json'
    }
}

# Build the Git URL to include the Git user credentials
$builder = [UriBuilder]::new($AWSAssets.CCRepo.CloneUrlHttp)
$builder.UserName = $AWSAssets.CCGitUserCredentials.UserName
$builder.Password = $AWSAssets.CCGitUserCredentials.GetNetworkCredential().Password


# Configure the deployment settings on the Azure Web App to use the AWS CodeCommit Repository
$Params = @{
    PropertyObject    = @{
        repoUrl = $builder.ToString()
        branch = "master"
        isManualIntegration = $true
        deploymentRollbackEnabled = $false
        isMercurial = $false
    }
    ResourceGroupName = $Settings.ResourceGroupName 
    ResourceType      = 'Microsoft.Web/sites/SourceControls'
    ResourceName      = '{0}/web' -f $Settings.ResourceGroupName
    ApiVersion        = '2015-08-01'
    force             = $true
}
$AzureAssets['WebAppDeploymentSettingsSet'] = Set-AzureRmResource @Params -ErrorAction 'SilentlyContinue'

Describe "Azure Web App Deployment Settings" {
    It "Was configured for CodeCommit" {
        $Params = @{
            ResourceGroupName = $Settings.ResourceGroupName 
            ResourceType      = 'Microsoft.Web/sites/SourceControls'
            ResourceName      = '{0}/web' -f $Settings.ResourceGroupName
            ApiVersion        = '2015-08-01'
        }
        $AzureAssets['WebAppDeploymentSettingsGet'] = Get-AzureRmResource @Params
        $Result = $AzureAssets.WebAppDeploymentSettingsGet

        $Result.Properties.repoUrl | Should -BeExactly $builder.ToString()
        $Result.Properties.branch | Should -BeExactly 'master'
        $Result.Properties.isManualIntegration | Should -BeExactly $true
        $Result.Properties.isMercurial | Should -BeExactly $false
        $Result.Properties.deploymentRollbackEnabled | Should -BeExactly $false
    }
    It "Successfully provisioned from AWS CodeCommit" {
        $AzureAssets['WebAppDeploymentSettingsGet'].Properties.provisioningState | Should -BeExactly 'Succeeded'
    }
}



# Copy the Sample function app, commit the changes and push to AWS CodeCommit
Copy-Item -Recurse ('{0}\*' -f $Settings.SrcDirectory) -Destination .
git add -A
git commit -m 'Add Example Function'
git push origin master

##### Diagnostics and Cleanup
$null = Start-AzureRmWebApp -WebApp $AzureAssets['WebbApps'][0]

Remove-AzureRmResourceGroup -Name $Settings.ResourceGroupName -Force
Remove-CCRepository -RepositoryName $Settings.CCRepoName -Force
Remove-IAMUser -UserName $Settings.CCGitUser -Force
Pop-Location; Pop-Location
Remove-Item -force -Recurse -confirm:$false $Settings.GitDirectory
Remove-Item -force -Recurse $Settings.ResourceGroupName