namespace PBnCLambda
{
    public class Cc2AfConfig
    {
        public string DeploymentUser { get; set; }
        public string DeploymentPassword { get; set; }
        public string DeploymentTriggerUrl { get; set; }
        public string DeploymentAppName { get; set; }

        public string CodeCommitUser { get; set; }
        public string CodeCommitPassword { get; set; }
        public string CodeCommitBranch { get; set; }
    }
}