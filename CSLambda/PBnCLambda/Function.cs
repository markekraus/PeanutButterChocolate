using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Amazon.Lambda.Core;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Amazon.CodeCommit;
using Amazon.CodeCommit.Model;
using Newtonsoft.Json;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace PBnCLambda
{
    public class Function
    {

        /// <summary>
        /// A function to handle a CodeCommit Event.
        /// </summary>
        /// <param name="commitEvent"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public void FunctionHandler(CodeCommitEvent commitEvent, ILambdaContext context)
        {
            string repoName = commitEvent.Records[0].RepositoryName;
            string branch = commitEvent.Records[0].codecommit.references[0].Branch;
            string commit = commitEvent.Records[0].codecommit.references[0].commit;
            var codeCommit = new AmazonCodeCommitClient();
            var repo = codeCommit.GetRepositoryAsync( new GetRepositoryRequest() {RepositoryName = repoName}).GetAwaiter().GetResult();
            var differences = GetDifferences(codeCommit, repoName, commit);

            var sns = new AmazonSimpleNotificationServiceClient();
            var publishRequest = new PublishRequest();
            publishRequest.Message = $"Repo: {commitEvent.Records[0].RepositoryName}; CommitId: {commitEvent.Records[0].codecommit.references[0].commit}; Ref: {commitEvent.Records[0].codecommit.references[0].@ref}";
            publishRequest.Subject = "Test SNS";
            publishRequest.TopicArn = "arn:aws:sns:us-east-1:099223339714:TestTrigger";
            var result = sns.PublishAsync(publishRequest).GetAwaiter().GetResult();
            Console.WriteLine(JsonConvert.SerializeObject(result));
        }

        private List<Difference> GetDifferences (AmazonCodeCommitClient codeCommit, string repositoryName, string afterCommitSpecifier)
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
    }
}
