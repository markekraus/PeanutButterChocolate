import boto3
import pathlib
import tarfile
import io
import sys

# Adapted from https://stackoverflow.com/a/46297369/8136208

def get_differences(repository_name, branch="master"):
    response = codecommit.get_differences(
        repositoryName=repository_name,
        afterCommitSpecifier=branch,
    )
    differences = []
    while "nextToken" in response:
        response = codecommit.get_differences(
            repositoryName=repository_name,
            afterCommitSpecifier=branch,
            nextToken=response["nextToken"]
        )
        differences += response.get("differences", [])
    else:
        differences += response["differences"]
    return differences


if __name__ == "__main__":
    repository_name = sys.argv[1]
    codecommit = boto3.client("codecommit")
    repository_path = pathlib.Path(repository_name)
    buf = io.BytesIO()
    with tarfile.open(None, mode="w:gz", fileobj=buf) as tar:
        for difference in get_differences(repository_name):
            blobid = difference["afterBlob"]["blobId"]
            path = difference["afterBlob"]["path"]
            mode = difference["afterBlob"]["mode"]  # noqa
            blob = codecommit.get_blob(
                repositoryName=repository_name, blobId=blobid)
            tarinfo = tarfile.TarInfo(str(repository_path / path))
            tarinfo.size = len(blob["content"])
            tar.addfile(tarinfo, io.BytesIO(blob["content"]))
    tarobject = buf.getvalue()