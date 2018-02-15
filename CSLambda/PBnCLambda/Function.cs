using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Lambda.Core;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Amazon.CodeCommit;
using Amazon.CodeCommit.Model;
using Newtonsoft.Json;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using System.Net.Http;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace PBnCLambda
{
    public class Function
    {

        private static string ConfigPathEnvVar = "CC2AF_CONFIG_PATH";
        private static string ConfigPathDefault = "cc2af.yaml";
        private static string SrcBranchDefault = "master";
        
        private static HttpClient Http = new HttpClient();
        
        /// <summary>
        /// A function to handle a CodeCommit Event.
        /// </summary>
        /// <param name="commitEvent"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public void FunctionHandler(CodeCommitEvent commitEvent, ILambdaContext context)
        {
            string repositoryName = commitEvent.Records[0].RepositoryName;
            string branch = commitEvent.Records[0].codecommit.references[0].Branch;
            string commit = commitEvent.Records[0].codecommit.references[0].commit;

            string configPath = Environment.GetEnvironmentVariable(ConfigPathEnvVar);
            configPath = String.IsNullOrWhiteSpace(configPath) ? ConfigPathDefault : configPath;

            var codeCommit = new AmazonCodeCommitClient();
            var repository = codeCommit.GetRepositoryAsync( 
                new GetRepositoryRequest() {RepositoryName = repositoryName}
            ).GetAwaiter().GetResult();
            
            var config = GetCc2AfConfig(codeCommit, repositoryName, commit, configPath);

            var srcBranch = String.IsNullOrWhiteSpace(config.CodeCommitBranch) ? SrcBranchDefault : config.CodeCommitBranch;

            HttpResponseMessage response = null;
            if (branch == srcBranch)
            {
                var deploymentPassword = ConvertFromEncryptedBase64(config.DeploymentPassword);
                var codeCommitPassword = ConvertFromEncryptedBase64(config.CodeCommitPassword);

                response = InvokeDeployment(http:               Http,
                                                deploymentAppUrl:   config.DeploymentTriggerUrl,
                                                deploymentAppName:  config.DeploymentAppName,
                                                deploymentUser:     config.DeploymentUser,
                                                deploymentPassword: deploymentPassword,
                                                codeCommitHttpsUrl: repository.RepositoryMetadata.CloneUrlHttp,
                                                codeCommitUser:     config.CodeCommitUser,
                                                codeCommitPassword: codeCommitPassword);

                
            }
            WriteResults(response, configPath, config, repository, repositoryName, branch, commit, srcBranch);
        }

        public static void WriteResults(HttpResponseMessage response, string configPath, Cc2AfConfig config, GetRepositoryResponse repository, string repositoryName, string branch, string commit, string srcBranch)
        {
            var dictionary = new Dictionary<string,object>(){
                {"Response", response},
                {"ConfigPath", configPath},
                {"Config", config},
                {"Repository", repository},
                {"RepositoryName", repositoryName},
                {"Branch", branch},
                {"Commit", commit},
                {"SrcBranch", srcBranch}
            };
            Console.WriteLine(JsonConvert.SerializeObject(dictionary));
        }

        public static string ConvertFromEncryptedBase64 (string encryptedBase64)
        {
            string result;
            using (var kms = new AmazonKeyManagementServiceClient())
            {
                var response = kms.DecryptAsync(new DecryptRequest(){
                    CiphertextBlob = new MemoryStream(Convert.FromBase64String(encryptedBase64))
                }).GetAwaiter().GetResult();
                using (TextReader reader = new StreamReader(response.Plaintext))
                {
                    result = reader.ReadToEnd();
                }
            }
            return result;
        }

        public static Cc2AfConfig GetCc2AfConfig(AmazonCodeCommitClient codeCommit, string repositoryName, string afterCommitSpecifier, string configPath)
        {
            Cc2AfConfig result;
            var differences = GetDifferences(codeCommit, repositoryName, afterCommitSpecifier);

            var configDiff = GetConfigurationDifference(differences, configPath);
            if (configDiff == null)
            {
                var ex = new FileNotFoundException("Unable to find Cc2Fa Configuration YAML file.", configPath);
                throw ex;
            }

            var configBlob = codeCommit.GetBlobAsync(new GetBlobRequest(){
                BlobId = configDiff.AfterBlob.BlobId,
                RepositoryName = repositoryName
            }).GetAwaiter().GetResult();

            var yamlDeserializer = new DeserializerBuilder().WithNamingConvention(new CamelCaseNamingConvention()).Build();
            using (TextReader reader = new StreamReader(configBlob.Content))
            {
                result = yamlDeserializer.Deserialize<Cc2AfConfig>(reader);
            }
            return result;
        }
        public static List<Difference> GetDifferences (AmazonCodeCommitClient codeCommit, string repositoryName, string afterCommitSpecifier)
        {
            var result = new List<Difference>();
            GetDifferencesResponse response;
            string nextToken = String.Empty;
            do
            {
                response = codeCommit.GetDifferencesAsync(new GetDifferencesRequest() {
                    RepositoryName = repositoryName, 
                    AfterCommitSpecifier = afterCommitSpecifier,
                    NextToken = nextToken
                }).GetAwaiter().GetResult();

                result.AddRange(response.Differences);
                nextToken = response.NextToken;
            } while (!String.IsNullOrEmpty(nextToken));

            return result;
        }

        public static Difference GetConfigurationDifference(IList<Difference> differences, string configPath)
        {
            Difference result;
            result = differences.Where( d => d.AfterBlob.Path == configPath).FirstOrDefault();
            return result;
        }

        public static HttpResponseMessage InvokeDeployment(HttpClient http, string deploymentAppUrl, string deploymentUser, string deploymentPassword, string deploymentAppName, string codeCommitUser, string codeCommitPassword, string codeCommitHttpsUrl)
        {
            var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{deploymentUser}:{deploymentPassword}"));
            var request = new HttpRequestMessage();
            request.Headers.Add("Authorization", $"Basic {auth}");
            request.Headers.Add("X-SITE-DEPLOYMENT-ID",deploymentAppName);
            request.RequestUri = new Uri(deploymentAppUrl);
            request.Method = HttpMethod.Post;

            var builder = new UriBuilder(codeCommitHttpsUrl);
            builder.UserName = codeCommitUser;
            builder.Password = deploymentPassword;

            var bodyString = JsonConvert.SerializeObject(new Dictionary<string,string>(){
                {"format", "basic"},
                {"url", builder.ToString()}
            });
            var bodyBytes = Encoding.UTF8.GetBytes(bodyString);
            request.Content = new ByteArrayContent(bodyBytes);

           return http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        }
    }
}
