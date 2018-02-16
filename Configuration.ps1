# Install and Import AzureRM Module
Install-Module AzureRM -Scope CurrentUser -Force -MinimumVersion 5.2.0
Import-Module AzureRM -Force -MinimumVersion 5.2.0

# Install and Import the AWSPowerShell module
Install-Module -Name AWSPowerShell -Scope CurrentUser -Force -MinimumVersion 3.3.232.0
Import-Module -MinimumVersion 3.3.232.0 -Name AWSPowerShell

# Install and Import Pester
Install-Module Pester -Scope CurrentUser -Force -MinimumVersion 4.1.1
Import-Module Pester -Force -MinimumVersion 4.1.1

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
    RsourceTemplateUrl            = 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-function-app-create-dynamic/azuredeploy.json'
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
    CCTriggerName                 = 'TriggerAzureFunctionDeployment'
    LambdaName                    = 'TriggerAzureFunctionDeployment'
    LambdaHandler                 = 'PBnCLambda::PBnCLambda.Function::FunctionHandler'
    LambdaRuntime                 = 'dotnetcore2.0'
    LambdaDescription             = 'Triggers a manual deployment of an Azure Web App from CodeCommit.'
    LambdaRoleName                = 'TriggerAzureFunctionDeploymentRole'
    LambdaRoleDescription         = 'Role assumed by the TriggerAzureFunctionDeployment Lambda'
    LambdaSrcDirectory            = Join-Path $BaseDir 'CSLambda\PBnCLambda\'
    LambdaTimeOut                 = 300
    LambdaMemorySize              = 512
    KMSKeyDescription             = 'Key Used by TriggerAzureFunctionDeployment to manage config secrets.'
    KMSRoleAccessPolicyName       = 'KMS-Key-Access-{0}' -f [Guid]::NewGuid()
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
$Params = @{
    TemplateUri        = $Settings.RsourceTemplateUrl
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
}

# Grab the PublishProfile for the Web App. This gives us the deployment username and password
$AzureAssets['WebAppPublishingProfile'] = [xml](Get-AzureRmWebAppPublishingProfile -WebApp $AzureAssets['WebbApps'][0])
$AzureAssets['WebAppUserName'] = $AzureAssets['WebAppPublishingProfile'].publishData.publishProfile[0].userName
$AzureAssets['WebAppUserPwd'] = $AzureAssets['WebAppPublishingProfile'].publishData.publishProfile[0].userPWD
$AzureAssets['WebAppDeployUrl'] = 'https://{0}.scm.azurewebsites.net:443/deploy' -f 
    $AzureAssets.ResourceGroup.ResourceGroupName

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

# Before continuing, make sure you have configured an SSH key for AWS CodeCommit on your admin account

# Create the Git Directory and change location to it
$Null = New-Item -ItemType Directory -Path $Settings.GitDirectory -Force -ErrorAction 'SilentlyContinue'
Push-Location $Settings.GitDirectory

# Clone the empty CodeCommit repository
git clone $AWSAssets.CCRepo.CloneUrlSsh
Push-Location $Settings.CCRepoName

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
$builder.Password = [uri]::EscapeDataString($AWSAssets.CCGitUserCredentials.GetNetworkCredential().Password)


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

# Create an IAM role for the lambda 
$AssumeRolePolicyDocument = @"
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
"@
$Params = @{
    AssumeRolePolicyDocument = $AssumeRolePolicyDocument
    RoleName                 = $Settings.LambdaRoleName
    Description              = $Settings.LambdaRoleDescription
}
$AWSAssets['LambdaRole'] = New-IAMRole @Params

# Attach the IAM policies to the lambda IAM Role
$PolicyArns = @(
    'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    'arn:aws:iam::aws:policy/AWSCodeCommitReadOnly'
)
foreach ($PolicyArn in $PolicyArns) {
    $PolicyArnsConfigured
    $Params = @{
        PolicyArn = $PolicyArn
        RoleName = $Settings.LambdaRoleName
    }
    Register-IAMRolePolicy @Params
}

Describe 'AWS Lambda Role' {
    BeforeAll {
        $AWSAssets['LambdaAttachedPolicies'] = Get-IAMAttachedRolePolicyList -RoleName $Settings.LambdaRoleName
    }
    It "Was successfully created" {
        $role = Get-IAMRole -RoleName $Settings.LambdaRoleName
        $policDocument = [uri]::UnescapeDataString($role.AssumeRolePolicyDocument) | ConvertFrom-Json

        $role.RoleName | should -BeExactly $Settings.LambdaRoleName
        $role.Description | should -BeExactly $Settings.LambdaRoleDescription
        $policDocument.Statement[0].Effect | should -BeExactly 'Allow'
        $policDocument.Statement[0].Principal.Service | should -BeExactly 'lambda.amazonaws.com'
        $policDocument.Statement[0].Action | should -BeExactly "sts:AssumeRole"
    }

    It "Has the <PolicyArn> Policy attached" -TestCases @(
        foreach($PolicyArn in $PolicyArns){ @{PolicyArn = $PolicyArn }}
    ) {
        param($PolicyArn)
        $PolicyArn | Should -BeIn $AWSAssets['LambdaAttachedPolicies'].PolicyArn
    }
}

# Build, and zip the C# Lambda trigger
Push-Location $Settings.LambdaSrcDirectory
dotnet publish -c release
$PublishPath = Join-Path $pwd 'bin\release\netcoreapp2.0\publish\*'
$Tempfile = New-TemporaryFile
$newname = '{0}.zip' -f $Tempfile.BaseName
$Tempfile = $Tempfile | Rename-Item -NewName $newname -PassThru
Compress-Archive -Path $PublishPath -DestinationPath $Tempfile -Force
Pop-Location

# Publish the Lambda that will trigger the Azure Deployment when a CodeCommit push occurs
$Params = @{
    FunctionName = $Settings.LambdaName
    Description  = $Settings.LambdaDescription
    ZipFilename  = $Tempfile.FullName
    Handler      = $Settings.LambdaHandler
    Runtime      = $settings.LambdaRuntime
    Force        = $true
    Role         = $AWSAssets.LambdaRole.Arn
    Timeout      = $Settings.LambdaTimeOut
    MemorySize   = $Settings.LambdaMemorySize
}
$AWSAssets['PublishedLambda'] = Publish-LMFunction @Params 

Describe "AWS Lambda Function" {
    It "was published successfully" {
        $lambda = Get-LMFunction -FunctionName $Settings.LambdaName
        $config = $lambda.Configuration

        $config.Role | should -BeExactly $AWSAssets.LambdaRole.Arn
        $config.Runtime | should -BeExactly $Settings.LambdaRuntime
        $config.FunctionName | should -BeExactly $Settings.LambdaName
        $config.Handler | should -BeExactly $Settings.LambdaHandler
        $config.Description | should -BeExactly $Settings.LambdaDescription
        $config.Timeout | should -Be $Settings.LambdaTimeOut
    }
}

# Create AWS KMS Key used to secure secrets in the configuration YAML
$AWSAssets['KMSKey'] = New-KMSKey -Description $Settings.KMSKeyDescription
$AWSAssets.KMSKey

Describe "AWS KMS Key" {
    It "Was successfully created" {
        $key = Get-KMSKey -KeyId $AWSAssets.KMSKey.KeyId

        $key.Description | should -BeExactly $Settings.KMSKeyDescription
    }
}

$PolicyDocument = @"
{
    "Version": "2012-10-17",
    "Statement": {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt"
      ],
      "Resource": [
        "$($AWSAssets.KMSKey.Arn)"
      ]
    }
  }
"@
$Params = @{
    PolicyDocument = $PolicyDocument
    PolicyName     = $Settings.KMSRoleAccessPolicyName
    RoleName       = $Settings.LambdaRoleName
    PassThru       = $true
}
$AWSAssets['KMSRoleAccessPolicy'] =  Write-IAMRolePolicy @Params 

Describe "Lambda Role KMS Access Policy" {
    It "Was successfully created" {
        $policy = Get-IAMRolePolicy -RoleName $Settings.LambdaRoleName -PolicyName $Settings.KMSRoleAccessPolicyName
        $policydoc = [uri]::UnEscapeDataString($policy.PolicyDocument) | ConvertFrom-Json

        $policy.RoleName | should -BeExactly $Settings.LambdaRoleName
        $policy.PolicyName | should -BeExactly $Settings.KMSRoleAccessPolicyName
        $policydoc.Statement.Action.Count | should -be 2
        "kms:Encrypt", "kms:Decrypt" | should -BeIn $policydoc.Statement.Action
        $policydoc.Statement.Effect | should -BeExactly 'Allow'
        $policydoc.Statement.Resource | should -BeExactly $AWSAssets.KMSKey.Arn
    }
}

# Grant the CodeCommit Repo access to execute the Lambda function
$Params = @{
    Action       = 'lambda:InvokeFunction'
    FunctionName = $Settings.LambdaName 
    Principal    = 'codecommit.amazonaws.com'
    SourceArn    = $AWSAssets.CCRepo.Arn
    StatementId  = '{0}-{1}' -f $Settings.LambdaName, [Guid]::NewGuid()
}
$AWSAssets['CCLambdaPermission'] = Add-LMPermission @Params -Force
 
# Add Trigger to the CodeCommit Repository to Execute the Lambda function
$repoTrigger = [Amazon.CodeCommit.Model.RepositoryTrigger]::New()
$repoTrigger.Branches.Add('master')
$repoTrigger.DestinationArn = $AWSAssets.PublishedLambda.FunctionArn
$repoTrigger.Events = 'all'
$repoTrigger.Name = $Settings.CCTriggerName
$Params = @{
    RepositoryName = $Settings.CCRepoName
    Trigger        = $repoTrigger 
    Force          = $true
}
$AWSAssets['CCRepositoryTrigger'] =  Set-CCRepositoryTrigger @Params

describe "CodeCommit Repository Trigger" {
    it "Was successfully added." {
        $triggers = Get-CCRepositoryTrigger -RepositoryName $Settings.CCRepoName

        $triggers.Triggers[0].Branches.Count | should -be 1
        $triggers.Triggers[0].Branches[0] | should -BeExactly 'master'
        $triggers.Triggers[0].DestinationArn | should -BeExactly $AWSAssets.PublishedLambda.FunctionArn
        $triggers.Triggers[0].Name | should -BeExactly $Settings.CCTriggerName
    }
}


# Encrypt the CodeCommit Git User Password and base64 encode it
$byteArray = [System.Text.Encoding]::UTF8.GetBytes($AWSAssets.CCGitUserCredentials.GetNetworkCredential().password)
$memoryStream = [System.IO.MemoryStream]::new($ByteArray)
$encryptedStream = (Invoke-KMSEncrypt -KeyId $AWSAssets.KMSKey.KeyId -Plaintext $memoryStream).CiphertextBlob
$AWSAssets['EncryptedGitPassword'] = [System.Convert]::ToBase64String($encryptedStream.ToArray())

# Encrypt the CodeCommit Git User Password and base64 encode it
$byteArray = [System.Text.Encoding]::UTF8.GetBytes($AzureAssets.WebAppUserPwd)
$memoryStream = [System.IO.MemoryStream]::new($ByteArray)
$encryptedStream = (Invoke-KMSEncrypt -KeyId $AWSAssets.KMSKey.KeyId -Plaintext $memoryStream).CiphertextBlob
$AzureAssets['EncryptedWebAppPassword'] = [System.Convert]::ToBase64String($encryptedStream.ToArray())

# Generate the cc2af.yml which is used by the TriggerAzureFunctionDeployment Lambda 
# to preform the deployment triggers.
$cc2afyml = @"
# All settings are case sensitive

# Azure Web App Deployment Username
DeploymentUser: {0}

# Azure Web App Deployment Password (Encrypted with KMS key)
DeploymentPassword: {1}

# Azure Web App Deployment URL (without the username and password)
# Looks like https://MyApp.scm.azurewebsites.net/deploy
DeploymentTriggerUrl: {2}

# Azure Web App Name
DeploymentAppName: {3}

# HTTPS Git credentials for AWS CodeCommit Username
CodeCommitUser: {4}

# HTTPS Git credentials for AWS CodeCommit Password (encrypted with KMS)
CodeCommitPassword: {5}

# The CodeCommit Branch to deploy from. Commits to other branches will be ignored.
CodeCommitBranch: master
"@ -f @(
    $AzureAssets.WebAppUserName
    $AzureAssets.EncryptedWebAppPassword
    $AzureAssets.WebAppDeployUrl
    $Settings.ResourceGroupName
    $AWSAssets.CCGitUserCredentials.UserName
    $AWSAssets.EncryptedGitPassword
)
$cc2afyml | Set-Content 'cc2af.yml' -Encoding UTF8

# Copy the Sample function app, commit, then push
Copy-Item -Recurse ('{0}\*' -f $Settings.SrcDirectory) -Destination .
git add -A
git commit -m 'Add Example Function'
git push origin master

##### Diagnostics and Cleanup
$null = Start-AzureRmWebApp -WebApp $AzureAssets['WebbApps'][0]

Remove-AzureRmResourceGroup -Name $Settings.ResourceGroupName -Force
Remove-CCRepository -RepositoryName $Settings.CCRepoName -Force
Get-IAMUserPolicyList -UserName $Settings.CCGitUser | ForEach-Object {
    Remove-IAMUserPolicy -UserName $Settings.CCGitUser -PolicyName $_ -Force
}
Remove-IAMUser -UserName $Settings.CCGitUser -Force
Unregister-IAMRolePolicy -PolicyArn $PolicyArns[0] -RoleName $Settings.LambdaRoleName
Unregister-IAMRolePolicy -PolicyArn $PolicyArns[1] -RoleName $Settings.LambdaRoleName
Remove-IAMRole -RoleName $Settings.LambdaRoleName -force
Pop-Location; Pop-Location
Remove-Item -force -Recurse -confirm:$false $Settings.GitDirectory
Remove-Item -force -Recurse $Settings.ResourceGroupName