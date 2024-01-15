# api-gateway-apple-authorizer

This project contains the source code for the `api-gateway-apple-authorizer` lambda function which will authorize Api Gateway requests to user-defined routes.

---

### Disclaimer
I am in no way stating that this is a hardened piece of software intended for production use. It is merely code that I have personally used in the past in order to experiment with Apple's APIs. **Use at your own risk.**

---

#### Purpose
This lambda will be most useful to you if you are looking to use Apple's *Sign In With Apple* bearer tokens to authorize iOS HTTP calls against your Api Gateway instance.

#### Prerequisites
You will need a deployed Api Gateway stage in addition to an iOS app that uses Apple's *Sign In With Apple* capability.

## How to Deploy
You can pull this repository yourself and build/deploy the serverless application manually with SAM, however, deploying via the AWS Serverless Application Repository (SAR) is typically much quicker and easier.

### SAM Manual Deployment
We assume the user has the capabilities to deploy a SAM app, so we will not detail them here. Please see [this documentation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-command-reference.html) if you aren't familiar with this AWS sdk.

### AWS Serverless Application Repository (SAR)
To deploy using the preferred option of SAR, you will need to open AWS SAR (through the AWS console) and search the public applications for *api-gateway-apple-authorizer*. Once you've found it, you'll see that you are required to enter two environment variables that the authorizer will use to properly validate requests coming from your iOS app:
- `AllowResourceArn`: this parameter is used in crafting the `Resource` section of the authorizer's IAM policy response. For example, if your Api Gateway has an instance id of `abcdefg` and you'd like to grant permissions to all routes in the `prod` stage, this string would look something like this: `arn:aws:execute-api:<region>:<acctId>:abcdefg/prod/*`
- `Audience`: This is the bundle identifier of your iOS app. It will look something like `com.example.myapp`