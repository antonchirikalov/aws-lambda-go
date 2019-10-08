# aws-lambda-go

## Requirements

* AWS CLI already configured with Administrator permission
* [Go 1.x installed](https://golang.org/doc/install)
* [Docker installed](https://hub.docker.com/editions/community/docker-ce-desktop-mac)

## Setup process

### Local development

**Install AWS Serverless Application Model (SAM) CLI**

You can find complete instructions [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html).  Instructions for MacOS with homebrew are as follows:

```bash
brew tap aws/tap
brew install aws-sam-cli
```

**Download Lambda Go Docker container**

```bash
docker pull lambci/lambda:go1.x
```

**Building functions locally**

Path is relative to ./src and does not contain filename.

```bash
make build lambda=test/sample
```

**Invoking function locally using a sample empty event**

Function must be defined in template.yaml. Event is relative to ./src/events

```bash
make invoke func=TestFunction event=empty.json
```

**Invoking function locally through local API Gateway**

```bash
make start
```

If the previous command ran successfully you should now be able to interact with your function `http://localhost:9000/{path}`

**Deployment**

There is a 3-part process to prepare and deploy our lambdas.  Each of the lambdas need to be built in a specific way, uploaded to S3 and template.yml needs the CodeUris converted to S3 URIs before actually deploying to AWS.  You can perform each of these steps individually, or run them all with `bpd` (build package deploy).

```bash
make bpd stack=MyTS
```

Reference the Makefile if you'd like to run these steps independently.
