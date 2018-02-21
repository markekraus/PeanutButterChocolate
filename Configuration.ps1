# Install and Import AzureRM Module
Install-Module AzureRM -Scope CurrentUser -Force -MinimumVersion 5.2.0
Import-Module AzureRM -Force -MinimumVersion 5.2.0

# Install and Import the AWSPowerShell module
Install-Module -Name AWSPowerShell -Scope CurrentUser -Force -MinimumVersion 3.3.232.0
Import-Module -MinimumVersion 3.3.232.0 -Name AWSPowerShell

# Install and Import Pester 4.2.0
# This script makes use of features only available in Pester 4.2.0 and up
Install-Module Pester -Scope CurrentUser -Force -MinimumVersion 4.2.0
Import-Module Pester -Force -MinimumVersion 4.2.0

# Before continuing, make sure you have configured an SSH key for AWS CodeCommit on your admin account
# https://docs.aws.amazon.com/codecommit/latest/userguide/setting-up-ssh-windows.html



# Prompt for the AWS Admin access Key and Secret Key
$AWSCredentials = Get-Credential -Message 'AWS Access Key and Secret Key'

# set the Base Directory for the project
$BaseDir = $PWD
if ($PSScriptRoot) { 
    $BaseDir = $PSScriptRoot
}

# Settlings used by this project
$Settings = @{
    SrcDirectory                  = Join-Path $BaseDir 'src'
    # Folder under which the local Git repository will be cloned
    GitDirectory                  = 'c:\Git'
    # URL to the Azure Resource Template used to deploy the Azure Function Web App
    ResourceTemplateUrl            = 
        'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/57f091bc3c7d298e102ab092a1a25399b49d77f3/101-function-app-create-dynamic/azuredeploy.json'
    # New Azure Resource Group Name under which to deploy the Azure Web App and Storage
    ResourceGroupName             = 'PBnC'
    # The name to use for the Azure Function Web App
    AppName                       = 'PBnC'
    # See the -Location parameter of New-AzureRmResourceGroup for details
    ResourceGroupLocation         = "South Central US"
    # Options: Standard_LRS, Standard_GRS, Standard_RAGRS
    FunctionAppStorageAccountType = 'Standard_LRS'
    # The AWS Access Key and Secret key of the admin account used to configure AWS resources
    AwsAccessKey                  = $AWSCredentials.UserName
    AWSSecretKey                  = $AWSCredentials.GetNetworkCredential().Password
    # Name of an AWS credential profile to create and use to configure AWS resources
    AwsProfile                    = 'Aws01'
    # The AWS region in which to configure resources
    AwsRegion                     = 'us-east-2'
    # The Name to use for the CodeCommit Repository
    CCRepositoryName              = 'PBnC'
    # The Description to set on the CodeCommit Repository
    CCRepositoryDescription       = 'Peanut Butter and Chocolate'
    # Username of an IAM user to create. 
    # This user will granted pull access to the CodeCommit repository
    # Its HTTPS Git credentials for AWS CodeCommit will be used in azure to pull from the repository
    CCGitUser                     = 'PBnC-Git-User'
    # Name to use for the inline policy applied to the CCGitUser to allow pull access to the CodeCommit repository
    CCGitUserPolicyName           = 'Allow-GitPull-to-CodeCommit-PBnC'
    # Name to use for the CodeCommit repository trigger used to invoke the lambda function
    CCTriggerName                 = 'TriggerAzureFunctionDeployment'
    # Statement ID (SID) of the lambda policy to allow the CodeCommit repository to invoke the lambda
    CCLambdaPolicyStatementId     = 'CodeCommit-PBnC-Invoke-TriggerAzureFunctionDeployment'
    # Name of the AWS C# Lambda Function that CodeCommit will invoke to trigger Azure Web App Deployment
    LambdaName                    = 'TriggerAzureFunctionDeployment'
    # The Handler definition used by the C# Lambda Function
    LambdaHandler                 = 'PBnCLambda::PBnCLambda.Function::FunctionHandler'
    # The Runtime used by the AWS C# Lambda
    LambdaRuntime                 = 'dotnetcore2.0'
    # The description to set for the AWS C# Lambda
    LambdaDescription             = 'Triggers a manual deployment of an Azure Web App from CodeCommit.'
    # The name to give the IAM Role the AWS Lambda Function will assume when it is invoked
    LambdaRoleName                = 'TriggerAzureFunctionDeploymentRole'
    # The description to give the IAM Role the AWS Lambda Function will assume when it is invoked
    LambdaRoleDescription         = 'Role assumed by the TriggerAzureFunctionDeployment Lambda'
    # Manged IAM policies to apply to the IAM Role
    LambdaRolePolicyArns          = @(
        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        'arn:aws:iam::aws:policy/AWSCodeCommitReadOnly'
    )
    # Directory containing the C# .NET Core project for the AWS Lambda Function
    LambdaSrcDirectory            = Join-Path $BaseDir 'CSLambda\PBnCLambda\'
    # In testing, ths Lambda takes 2-5 seconds to run and consumes about 90MB of RAM
    # Timeout in seconds to set for the AWS Lambda Function executions
    LambdaTimeOut                 = 60
    # The memory size to use for the AWS Lambda Function
    LambdaMemorySize              = 128
    # Description to use for the AWS KMS key that will be generated
    # This key will be used by user to encrypt string in the cc2af.yml file
    # It will also be used by the AWS Lambda Function to decrypt those same strings
    KMSKeyDescription             = 'Key Used by TriggerAzureFunctionDeployment to manage config secrets.'
    # Name to set for the inline policy applied to the Lambda Role granting it access to the KMS Key
    KMSRoleAccessPolicyName       = 'Allow-TriggerAzureFunctionDeployment-Encrypt-Decrypt'
}

# Hashtables used for storing results from commands
$AzureAssets = @{}
$AWSAssets = @{}



# Log in to Azure
$AzureAssets['AccountLogin'] = Login-AzureRmAccount

# Create AWS credential profile and set it as the default configuration
Set-AWSCredential -StoreAs $Settings.AwsProfile -AccessKey $Settings.AwsAccessKey -SecretKey $Settings.AWSSecretKey
Initialize-AWSDefaultConfiguration -ProfileName $Settings.AwsProfile -Region $Settings.AwsRegion 



# Create the Resource Group and add a Function App Deployment
$Params = @{
    Name     = $Settings.ResourceGroupName
    Location = $Settings.ResourceGroupLocation
}
$AzureAssets['ResourceGroup'] = New-AzureRmResourceGroup @Params

# This Template deploys the storage account, App Service account, and Function App.
$Params = @{
    TemplateUri        = $Settings.ResourceTemplateUrl
    Name               = $Settings.ResourceGroupName
    ResourceGroupName  = $Settings.ResourceGroupName
    appName            = $Settings.AppName
    storageAccountType = $Settings.FunctionAppStorageAccountType
}
$AzureAssets['Deployment'] = New-AzureRmResourceGroupDeployment @Params -ErrorVariable 'DeploymentErrors' 

# Validate that the deployment was successful
Describe "Deployment of '$($Settings.ResourceGroupName)' Azure Function App" {
    It "Was Successful." {
        $DeploymentErrors | Should -HaveCount 0
        $AzureAssets.Deployment.ProvisioningState | Should -BeExactly 'Succeeded'
    }
    It "Has a Storage Account." {
        $AzureAssets['Storage'] = Get-AzureRmStorageAccount -ResourceGroupName $Settings.ResourceGroupName

        $AzureAssets.Storage.ProvisioningState | Should -BeExactly 'Succeeded'
    }
    It "Has an App Service Plan." {
        $AzureAssets['AppService'] = Get-AzureRmAppServicePlan -ResourceGroupName $Settings.ResourceGroupName

        $AzureAssets.AppService.Status | Should -BeExactly 'Ready'
        $AzureAssets.AppService.NumberOfSites | Should -Be 1
    }
    It "Has a Web App." {
        $AzureAssets['WebbApps'] = Get-AzureRmWebApp -ResourceGroupName $Settings.ResourceGroupName

        $AzureAssets.WebbApps | Should -HaveCount 1
        $AzureAssets.WebbApps[0].State | Should -BeExactly 'Running'
        $AzureAssets.WebbApps[0].SiteName | Should -Be $Settings.AppName
    }
}



# Grab the PublishProfile for the Web App. This gives us the deployment username and password
$AzureAssets['WebAppPublishingProfile'] = [xml](Get-AzureRmWebAppPublishingProfile -WebApp $AzureAssets.WebbApps[0])
$AzureAssets['WebAppUserName'] = $AzureAssets.WebAppPublishingProfile.publishData.publishProfile[0].userName
$AzureAssets['WebAppUserPwd'] = $AzureAssets.WebAppPublishingProfile.publishData.publishProfile[0].userPWD
$AzureAssets['WebAppDeployUrl'] = 'https://{0}.scm.azurewebsites.net:443/deploy' -f 
    $AzureAssets.ResourceGroup.AppName

# Create the Azure Web App Kudu Authorization header
# This is used to retrieve the Master key and Function key required to invoke the Azure Function
$AzureAssets['KuduAuth'] = 'Basic {0}' -f [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes(
        ('{0}:{1}' -f $AzureAssets.WebAppUserName, $AzureAssets.WebAppUserPwd)
    )
)



# Create the AWS CodeCommit Repository
$Params = @{
    RepositoryName        = $Settings.CCRepositoryName
    RepositoryDescription = $Settings.CCRepositoryDescription
}
$AWSAssets['CCRepository'] = New-CCRepository @Params -ErrorVariable 'CodeCommitRepositoryErrors'

# Validate the CodeCommit Repository was created
Describe "Deployment of '$($Settings.CCRepositoryName)' AWS CodeCommit Repository" {
    It "Was Successful." {
        $CCRepository = Get-CCRepository -RepositoryName $Settings.CCRepositoryName

        $CCRepository.RepositoryName | Should -BeExactly $Settings.CCRepositoryName
        $CCRepository.RepositoryDescription | Should -BeExactly $Settings.CCRepositoryDescription
    }
}



# Create a new AWS IAM User required for CodeCommit Git Credentials
$Params = @{
    UserName = $Settings.CCGitUser
    Force = $true
}
$AWSAssets['IAMUser'] = New-IAMUser @Params

# Create the IAM inline policy document and set it for the user
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
        "$($AWSAssets.CCRepository.Arn)"
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

# Validate the new user and inline policy were created successfully
Describe "AWS Git User" {
    It "Was successfully created" {
        $user = Get-IAMUser -UserName $Settings.CCGitUser
        $user.UserName | Should -BeExactly $Settings.CCGitUser
    }
    It "Has a policy attached" {
        $policy = Get-IAMUserPolicy -PolicyName $Settings.CCGitUserPolicyName -UserName $Settings.CCGitUser
        $PolicyObj = [uri]::UnescapeDataString($policy.PolicyDocument) | ConvertFrom-Json
        
        $PolicyObj.Statement[0].Effect | Should -BeExactly 'Allow'
        $PolicyObj.Statement[0].Action[0] | Should -BeExactly 'codecommit:GitPull'
        $PolicyObj.Statement[0].Resource[0] | Should -BeExactly $AWSAssets.CCRepository.Arn
    }
}




# Create the Git Directory and change location to it
$Null = New-Item -ItemType Directory -Path $Settings.GitDirectory -Force -ErrorAction 'SilentlyContinue'
Push-Location $Settings.GitDirectory

# Clone the empty CodeCommit repository
git clone $AWSAssets.CCRepository.CloneUrlSsh
Push-Location $Settings.CCRepositoryName

# Add an empty host.json file. This will let us confirm the Azure Web App Deployment settings are working
'{}' | Set-Content 'host.json'
git add -A
git commit -m 'Initial Commit'
git push --force

# Verify the initial commit was successful
Describe "Initial Git Commit" {
    It "Was successful" {
        $diffs = Get-CCDifferenceList -AfterCommitSpecifier "master" -RepositoryName $Settings.CCRepositoryName
        
        $diffs | Should -HaveCount 1
        $diffs[0].ChangeType | Should -BeExactly 'A'
        $diffs[0].AfterBlob.Path | Should -BeExactly 'host.json'
    }
}



# At this point we need to use the AWS web console to generate HTTPS Git credentials for AWS CodeCommit
# There is currently no public API for doing this outside of the AWS Web Console
$ConsoleUrl = 'https://console.aws.amazon.com/iam/home?region={0}#/users/{1}?section=security_credentials' -f 
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

# Build the Git URL to include the Git user credentials
$builder = [UriBuilder]::new($AWSAssets.CCRepository.CloneUrlHttp)
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
    ResourceName      = '{0}/web' -f $Settings.AppName
    ApiVersion        = '2015-08-01'
    force             = $true
}
$AzureAssets['WebAppDeploymentSettingsSet'] = Set-AzureRmResource @Params -ErrorAction 'SilentlyContinue'

# Validate the Deployment settings were successfully applied
Describe "Azure Web App Deployment Settings" {
    It "Was configured for CodeCommit" {
        $Params = @{
            ResourceGroupName = $Settings.ResourceGroupName 
            ResourceType      = 'Microsoft.Web/sites/SourceControls'
            ResourceName      = '{0}/web' -f $Settings.AppName
            ApiVersion        = '2015-08-01'
        }
        $AzureAssets['WebAppDeploymentSettingsGet'] = Get-AzureRmResource @Params
        $Result = $AzureAssets.WebAppDeploymentSettingsGet

        $Result.Properties.repoUrl | Should -BeExactly $builder.ToString()
        $Result.Properties.branch | Should -BeExactly 'master'
        $Result.Properties.isManualIntegration | Should -BeTrue
        $Result.Properties.isMercurial | Should -BeFalse
        $Result.Properties.deploymentRollbackEnabled | Should -BeFalse
    }
    It "Successfully provisioned from AWS CodeCommit" {
        $AzureAssets.WebAppDeploymentSettingsGet.Properties.provisioningState | Should -BeExactly 'Succeeded'
    }
}



# Create an IAM role for the AWS Lambda Function to assume
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

# Attach the IAM managed policies to the lambda IAM Role
# The WSLambdaBasicExecutionRole and AWSCodeCommitReadOnly policies should be sufficient
foreach ($PolicyArn in $Settings.LambdaRolePolicyArns) {
    $PolicyArnsConfigured
    $Params = @{
        PolicyArn = $PolicyArn
        RoleName = $Settings.LambdaRoleName
    }
    Register-IAMRolePolicy @Params
}

# Validate the IAM Role and Policies
Describe 'AWS Lambda Role' {
    BeforeAll {
        $AWSAssets['LambdaAttachedPolicies'] = Get-IAMAttachedRolePolicyList -RoleName $Settings.LambdaRoleName
    }
    It "Was successfully created" {
        $role = Get-IAMRole -RoleName $Settings.LambdaRoleName
        $policyDocument = [uri]::UnescapeDataString($role.AssumeRolePolicyDocument) | ConvertFrom-Json

        $role.RoleName | Should -BeExactly $Settings.LambdaRoleName
        $role.Description | Should -BeExactly $Settings.LambdaRoleDescription
        $policyDocument.Statement[0].Effect | Should -BeExactly 'Allow'
        $policyDocument.Statement[0].Principal.Service | Should -BeExactly 'lambda.amazonaws.com'
        $policyDocument.Statement[0].Action | Should -BeExactly "sts:AssumeRole"
    }

    It "Has the <PolicyArn> Policy attached" -TestCases @(
        foreach($PolicyArn in $Settings.LambdaRolePolicyArns){ @{PolicyArn = $PolicyArn }}
    ) {
        param($PolicyArn)
        $AWSAssets.LambdaAttachedPolicies.PolicyArn | Should -Contain $PolicyArn
    }
}



# Build, and zip the C# Lambda trigger
Push-Location $Settings.LambdaSrcDirectory
dotnet publish -c release
$PublishPath = Join-Path $pwd 'bin\release\netcoreapp2.0\publish\*'
$TempFile = New-TemporaryFile
$NewName = '{0}.zip' -f $TempFile.BaseName
$TempFile = $TempFile | Rename-Item -NewName $NewName -PassThru
Compress-Archive -Path $PublishPath -DestinationPath $TempFile -Force
Pop-Location



# Publish the AWS Lambda Function that will trigger the Azure Deployment when a CodeCommit push occurs
$Params = @{
    FunctionName = $Settings.LambdaName
    Description  = $Settings.LambdaDescription
    ZipFilename  = $TempFile.FullName
    Handler      = $Settings.LambdaHandler
    Runtime      = $settings.LambdaRuntime
    Force        = $true
    Role         = $AWSAssets.LambdaRole.Arn
    Timeout      = $Settings.LambdaTimeOut
    MemorySize   = $Settings.LambdaMemorySize
}
$AWSAssets['PublishedLambda'] = Publish-LMFunction @Params

# Clean up the temporary zip file
Remove-Item -Path $TempFile -Force -ErrorAction 'SilentlyContinue'

# Validate that the AWS lambda function has been published
Describe "AWS Lambda Function" {
    It "was published successfully" {
        $lambda = Get-LMFunction -FunctionName $Settings.LambdaName
        $config = $lambda.Configuration

        $config.Role | Should -BeExactly $AWSAssets.LambdaRole.Arn
        $config.Runtime | Should -BeExactly $Settings.LambdaRuntime
        $config.FunctionName | Should -BeExactly $Settings.LambdaName
        $config.Handler | Should -BeExactly $Settings.LambdaHandler
        $config.Description | Should -BeExactly $Settings.LambdaDescription
        $config.Timeout | Should -Be $Settings.LambdaTimeOut
    }
}



# Create AWS KMS Key used to secure secrets in the configuration YAML
$AWSAssets['KMSKey'] = New-KMSKey -Description $Settings.KMSKeyDescription
$AWSAssets.KMSKey

# Validate the key's creation
Describe "AWS KMS Key" {
    It "Was successfully created" {
        $key = Get-KMSKey -KeyId $AWSAssets.KMSKey.KeyId

        $key.Description | Should -BeExactly $Settings.KMSKeyDescription
    }
}



# Grant the IAM Role assumed by the AWS Lambda Function access to the KMS Key so it can decrypt
# secrets in the configuration YAML. 
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

# Validate the Key access policy has been applied
Describe "Lambda Role KMS Access Policy" {
    It "Was successfully created" {
        $policy = Get-IAMRolePolicy -RoleName $Settings.LambdaRoleName -PolicyName $Settings.KMSRoleAccessPolicyName
        $policyDocument = [uri]::UnEscapeDataString($policy.PolicyDocument) | ConvertFrom-Json

        $policy.RoleName | Should -BeExactly $Settings.LambdaRoleName
        $policy.PolicyName | Should -BeExactly $Settings.KMSRoleAccessPolicyName
        $policyDocument.Statement.Action | Should -HaveCount 2
        "kms:Encrypt", "kms:Decrypt" | Should -BeIn $policyDocument.Statement.Action
        $policyDocument.Statement.Effect | Should -BeExactly 'Allow'
        $policyDocument.Statement.Resource | Should -BeExactly $AWSAssets.KMSKey.Arn
    }
}



# Grant the CodeCommit Repository access to execute the Lambda function
$Params = @{
    Action       = 'lambda:InvokeFunction'
    FunctionName = $Settings.LambdaName 
    Principal    = 'codecommit.amazonaws.com'
    SourceArn    = $AWSAssets.CCRepository.Arn
    StatementId  = $Settings.CCLambdaPolicyStatementId
}
$AWSAssets['CCLambdaPermission'] = Add-LMPermission @Params -Force

# Validate the policy has been applied
Describe "CodeCommit Lambda policy" {
    It "Was successfully added" {
        $policy = Get-LMPolicy -FunctionName $Settings.LambdaName | 
            Select-Object -ExpandProperty Policy |
            ConvertFrom-Json
        $statement = $policy.Statement[0]

        $policy.Statement | Should -HaveCount 1
        $statement.Sid | Should -BeExactly $Settings.CCLambdaPolicyStatementId
        $statement.Effect | Should -BeExactly 'Allow'
        $statement.Principal.Service | Should -BeExactly 'codecommit.amazonaws.com'
        $statement.Condition.ArnLike.'AWS:SourceArn' | Should -BeExactly $AWSAssets.CCRepository.Arn
    }
}



# Add a Repository Trigger to the CodeCommit Repository to Execute the AWS Lambda function
$repositoryTrigger = [Amazon.CodeCommit.Model.RepositoryTrigger]::New()
$repositoryTrigger.Branches.Add('master')
$repositoryTrigger.DestinationArn = $AWSAssets.PublishedLambda.FunctionArn
$repositoryTrigger.Events = 'all'
$repositoryTrigger.Name = $Settings.CCTriggerName
$Params = @{
    RepositoryName = $Settings.CCRepositoryName
    Trigger        = $repositoryTrigger 
    Force          = $true
}
$AWSAssets['CCRepositoryTrigger'] =  Set-CCRepositoryTrigger @Params

# Validate the repository trigger
describe "CodeCommit Repository Trigger" {
    it "Was successfully added." {
        $triggers = Get-CCRepositoryTrigger -RepositoryName $Settings.CCRepositoryName

        $triggers.Triggers[0].Branches | Should -HaveCount 1
        $triggers.Triggers[0].Branches[0] | Should -BeExactly 'master'
        $triggers.Triggers[0].DestinationArn | Should -BeExactly $AWSAssets.PublishedLambda.FunctionArn
        $triggers.Triggers[0].Name | Should -BeExactly $Settings.CCTriggerName
    }
}



# The following two functions will be used to encrypt and decrypt secrets to store in the configuration YAML.
# The KeyId from the KMS key created earlier will be required in the future to encrypt new strings should 
# the publishing password change. The KeyId is not required for decrypt operations as it is embedded in the 
# encryption data.

# A function to encrypt a string with KMS and then return a base64 encoded string representation
function ConvertTo-Base64KMSEncryptedString {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [String[]]
        $String,

        [Parameter(
            Mandatory = $true
        )]
        [string]
        $KeyId,

        [hashtable]$EncryptionContext
    )
    
    process {
        foreach ($SourceString in $String) {
            $byteArray = [System.Text.Encoding]::UTF8.GetBytes($SourceString)
            $stringStream = [System.IO.MemoryStream]::new($ByteArray)
            try {
                $Params = @{
                    KeyId = $KeyId 
                    Plaintext = $stringStream 
                    ErrorAction = 'Stop'
                }
                if ($EncryptionContext) {
                    $Params['EncryptionContext'] = $EncryptionContext
                }
                $KMSResult = Invoke-KMSEncrypt @Params

                [System.Convert]::ToBase64String($KMSResult.CiphertextBlob.ToArray())
            }
            finally {
                if ($stringStream) { $stringStream.Dispose() }
                if ($KMSResult.CiphertextBlob) { $KMSResult.CiphertextBlob.Dispose() }
            }
        }
    }
}

# A function to decrypt a base64 representation of a string encrypted by KMS.
function ConvertFrom-Base64KMSEncryptedString {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [String[]]
        $EncryptedString,

        [hashtable]$EncryptionContext
    )
    
    process {
        foreach ($SourceString in $EncryptedString) {
            try{
                $byteArray = [System.Convert]::FromBase64String($SourceString)
            }
            Catch {
                Write-Error -ErrorRecord $_
                continue
            }
            $stringStream = [System.IO.MemoryStream]::new($byteArray)
            try {
                $Params = @{
                    CiphertextBlob = $stringStream 
                    ErrorAction = 'Stop'
                }
                if ($EncryptionContext) {
                    $Params['EncryptionContext'] = $EncryptionContext
                }
                $KMSResult = Invoke-KMSDecrypt @Params

                $reader = [System.IO.StreamReader]::new($KMSResult.Plaintext)
                $reader.ReadToEnd()
            }
            finally {
                if ($reader){ $reader.Dispose() }
                if ($stringStream){ $stringStream.Dispose() }
            }
        }
    }
}



# Encrypt the CodeCommit Git User Password and base64 encode it
$AWSAssets['EncryptedGitPassword'] = $AWSAssets.CCGitUserCredentials.GetNetworkCredential().password | 
    ConvertTo-Base64KMSEncryptedString -KeyId $AWSAssets.KMSKey.KeyId

# Encrypt the CodeCommit Git User Password and base64 encode it
$AzureAssets['EncryptedWebAppPassword'] = $AzureAssets.WebAppUserPwd | 
    ConvertTo-Base64KMSEncryptedString -KeyId $AWSAssets.KMSKey.KeyId



# Generate the cc2af.yml which is used by the TriggerAzureFunctionDeployment Lambda 
# to preform the deployment triggers.
$YamlConfigurationFile = @"
# All settings are Case Sensitive

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
    $Settings.AppName
    $AWSAssets.CCGitUserCredentials.UserName
    $AWSAssets.EncryptedGitPassword
)
$YamlConfigurationFile | Set-Content 'cc2af.yml' -Encoding UTF8



# Copy the Sample function app, commit, then push
Copy-Item -Recurse ('{0}\*' -f $Settings.SrcDirectory) -Destination .
git add -A
git commit -m 'Add Example Function'
git push origin master



# Wait several minutes for the deployment to complete.
# In testing this takes anywhere from a few seconds to a few minutes

# Get the Azure Functions available in the Azure Web App
$Params = @{
    ResourceGroupName = $Settings.ResourceGroupName
    ResourceType      = 'Microsoft.Web/sites/functions'
    ResourceName      = $Settings.AppName
    ApiVersion        = '2015-08-01'
}
$AzureAssets['AzureFunctions'] = Get-AzureRmResource @Params



# These headers are required by Kudu for several operations
$KuduHeaders = @{
    'Authorization' = $AzureAssets.KuduAuth
    'X-SITE-DEPLOYMENT-ID' = $Settings.AppName
}


# Get the Azure Web App deployment history
$params = @{
    uri = 'https://{0}.scm.azurewebsites.net/deployments' -f $Settings.AppName
    Headers = $KuduHeaders
    Method = 'GET'
}
$AzureAssets['FunctionDeployments'] = Invoke-RestMethod @Params


# Get the CloudWatch Log Stream for the AWS Lambda Function
$AWSAssets['LogGroupName'] = ('/aws/lambda/{0}' -f $Settings.LambdaName)
$AWSAssets['CloudWatchLogs'] = Get-CWLLogStream -LogGroupName $AWSAssets.LogGroupName -Descending $true 



# Validate the push to AWS CodeCommit resulted in a new Function being created in the Azure Function App
Describe "CodeCommit Deployment to Azure Functions" {
    It "Added a new function" {
        $functions = $AzureAssets.AzureFunctions
        $functions | Should -Not -BeNullOrEmpty
        $functions | Should -HaveCount 1
        # The name is determined by the function folder name in the src folder
        $functions[0].Properties.name | Should -BeExactly 'PBnC'
        $functions[0].Properties.config.disabled | Should -BeFalse
        $functions[0].Properties.config.bindings | Should -HaveCount 2
        $functions[0].Properties.config.bindings[0].authLevel | Should -BeExactly 'function'
        $functions[0].Properties.config.bindings[0].direction | Should -BeExactly 'in'
        $functions[0].Properties.config.bindings[0].type | Should -BeExactly 'httpTrigger'
        $functions[0].Properties.config.bindings[0].name | Should -BeExactly 'req'
        $functions[0].Properties.config.bindings[1].type | Should -BeExactly 'http'
        $functions[0].Properties.config.bindings[1].direction | Should -BeExactly 'out'
        $functions[0].Properties.config.bindings[1].name | Should -BeExactly 'res'
    }
    It "Was a successful deployment" {
        $deployments = $AzureAssets.FunctionDeployments
        $deployments | Should -HaveCount 2
        $deployment = $deployments[0]
        $deployment.active | Should -BeTrue
        $deployment.complete | Should -BeTrue
        $deployment.deployer | Should -Be ('git-codecommit.{0}.amazonaws.com' -f $Settings.AwsRegion)
        $deployment.message | Should -Match 'Add Example Function'
    }
}



# Display the Azure Web App Deployment Log and AWS CloudWatch Log for the Lambda
'----------------------- Azure Web App Deployment Log -----------------------------------'
Invoke-RestMethod -Headers $KuduHeaders -uri $AzureAssets.FunctionDeployments[0].log_url
'----------------------------------------------------------------------------------------'
' '
' '
'----------------------- AWS CloudWatch Log for Lambda ----------------------------------'
Get-CWLLogEvent -LogGroupName $AWSAssets.LogGroupName -LogStreamName $AWSAssets.CloudWatchLogs[0].LogStreamName |
    Select-Object -ExpandProperty Events |
    ForEach-Object {
        $_.IngestionTime.ToString()
        $_.message
    }
'----------------------------------------------------------------------------------------'



# Get the Azure Function App master key
$Params = @{
    Uri = "https://{0}.scm.azurewebsites.net/api/functions/admin/masterkey" -f $Settings.AppName
    Headers = $KuduHeaders + @{"If-Match"="*"} 
}
$maskterkey = Invoke-RestMethod @Params

# Get the Azure Function App function key
$Params = @{
    Uri = "https://{0}.azurewebsites.net/admin/functions/{1}/KEYS?CODE={2}" -f 
        $Settings.AppName, 'PBnC', $maskterkey.masterKey
}
$FunctionKeys = Invoke-RestMethod @Params



# Make an HTTP Trigger call to the actual Azure Function
$AzureAssets['AzureFunctionUrl'] = 'https://{0}.azurewebsites.net/api/{1}?code={2}&name=Mark%20Kraus' -f 
    $Settings.AppName, 'PBnC', $FunctionKeys.keys[0].value
$AzureAssets['AzureFunctionResult'] = Invoke-RestMethod -Uri $AzureAssets.AzureFunctionUrl

'--------------------------- Azure Function Result --------------------------------------'
$AzureAssets.AzureFunctionResult
'----------------------------------------------------------------------------------------'

# Validate the the Peanut Butter has been successfully put in the Chocolate
Describe "Peanut Butter" {
    It "Has been put in the Chocolate!!" {
        $AzureAssets.AzureFunctionResult | Should -Match 'Mark Kraus put Peanut Butter in the Chocolate!'
    }
}






##### Diagnostics and Cleanup
<#
# One command to remove all the Azure resources
Remove-AzureRmResourceGroup -Name $Settings.ResourceGroupName -Force

# Remove the CodeCommit Repository
Remove-CCRepository -RepositoryName $Settings.CCRepositoryName -Force
# You have to clear policies from a user before deleting them
Get-IAMUserPolicyList -UserName $Settings.CCGitUser | ForEach-Object {
    Remove-IAMUserPolicy -UserName $Settings.CCGitUser -PolicyName $_ -Force
}
# You have to delete the HTTPS Git Keys from the user in the AWS Web Console before you can remove the user
Remove-IAMUser -UserName $Settings.CCGitUser -Force
# Remove the custom inline policies from Lambda
Get-LMPolicy -FunctionName $Settings.LambdaName | ForEach-Object {
    $Policy = $_.Policy | ConvertFrom-Json
    foreach ($Statement in $Policy.Statement) {
        Remove-LMPermission -FunctionName $Settings.LambdaName -StatementId $Statement.Sid -Force
    }
}
# Remove the lambda
Remove-LMFunction -FunctionName $Settings.LambdaName -Force
# Remove the Managed policies from the role
$Settings.LambdaRolePolicyArns | ForEach-Object {
    $_
    Unregister-IAMRolePolicy -PolicyArn $_ -RoleName $Settings.LambdaRoleName
}
# remove the inline policies from the role
Get-IAMRolePolicyList -RoleName $Settings.LambdaRoleName | ForEach-Object {
    Remove-IAMRolePolicy -PolicyName $_ -RoleName $Settings.LambdaRoleName -Force
}
# Remove the Role
Remove-IAMRole -RoleName $Settings.LambdaRoleName -force


# Delete the KMS key in 7 days
Get-KMSKeyList | 
    ForEach-Object {Get-KMSKey -KeyId $_.KeyId} | 
    Where-Object {
        $_.Description -eq $Settings.KMSKeyDescription -and
        $_.Enabled     -eq $true
    } |
    ForEach-Object {
        Request-KMSKeyDeletion -KeyId $_.KeyId -PendingWindowInDay 7
        Get-KMSKey -KeyId $_.KeyId
    }
# Incase you change your mind run:
# Stop-KMSKeyDeletion -KeyId $key.KeyId

# Clean up local 
Pop-Location; Pop-Location
Remove-Item -force -Recurse -confirm:$false $Settings.GitDirectory
Remove-Item -force -Recurse $Settings.CCRepositoryName
#>
