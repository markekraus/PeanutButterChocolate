using System;

namespace PBnCLambda
{

    public class CodeCommitEventCodecommitReference
    {
        public string commit;
        public bool created = false;
        public string @ref;

        public string Branch
        {
            get
            {
                if (branch == null)
                {
                    try
                    {
                        branch = @ref.Split("/")[2];
                    }
                    catch
                    {
                        branch = String.Empty;
                    }
                }
                return branch;
            }
        }
        private string branch;
    }

    public class CodeCommitEventCodecommit
    {
        public CodeCommitEventCodecommitReference[] references;
    }

    public class CodeCommitEventRecord
    {
        public string awsRegion;
        public CodeCommitEventCodecommit codecommit;
        public Guid eventId;
        public string eventName;
        public Int64 eventPartNumber;
        public string eventSource;
        public string eventSourceARN;
        public string eventTime;
        public Int64 eventTotalParts;
        public Guid eventTriggerConfigId;
        public string eventTriggerName;
        public string eventVersion;
        public string userIdentityARN;
        public string RepositoryName
        {
            get
            {
                return eventSourceARN.Split(':')[5];
            }
        }
    }

    public class CodeCommitEvent
    {
        public CodeCommitEventRecord[] Records;
    }
}
