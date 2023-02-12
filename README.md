# A Google Client-Side Encryption API implementation.

## Architecture
KACLS relies on AWS configured using an active-active multi-region serverless architecture, specifically the ALB -> Lambda Target serverless pattern for lowest processing latencies. Encryption is done using KMS with the newer Multi-Region key replicas. Storage via DynamoDb multi-region Global Tables. All infrastructure is defined via AWS CDK v2 Infrastructure as Code.

Only cross regional dependencies are SSM paramaters stored in us-east-1 for communicating DNS Hosted Zone information, and KMS Primary Key information. A us-east-1 outage would prevent deployments during the outage, but not disrupt the service from running fully in other regions.

There are probably many ways to improve the CDK deployment described below, but I wanted the ability to control how stacks were deployed in each region, so most stacks that depend on other stacks, do so via CFN export/import, rather than passing TS values. From my experience this loose coupling means more orchestrating at deployment time, but provides better flexibility to make changes later.



## Deploy


### DNS

Deploy the DNS zone in `us-east-1`

```
cdk deploy KaclsDomainUsEast1Stack
```

After completing open the AWS web console and navigate to the zone in AWS Route 53, locate 4 NS records and add them to your DNS registrar's list of nameservers for your domain name. THis might take a while to propagate through the internet.

Then deploy to `us-west-2`
This does not deploy any DNS resources, but does make the hostedZoneID, the hostedZoneARN, and zoneName available in the region as CloudFormation exports

```
cdk deploy KaclsDomainUsWest2Stack
```


### ACM

Deploy the TLS Certs to ACM. First to `us-east-1`

```
cdk deploy KaclsCertUsEast1Stack
```

And again to `us-west-2`, as we want the regions to be as independent as possible.

```
cdk deploy KaclsCertUsWest2Stack
```


### KMS

Deploy the primary encryption key to `us-east-1`

```
cdk deploy KaclsEncKeyUsEast1Stack
```

And then a key replica to `us-west-2`

```
cdk deploy KaclsEncKeyUsWest2Stack
```


### VPC

Deploy the VPC needed by the ALB, fist in `us-east-1`

```
cdk deploy KaclsVpcUsEast1Stack
```

Deploy to us-west-2

```
cdk deploy KaclsVpcUsWest2Stack
```

### ALB & API



...


This is a blank project for CDK development with TypeScript.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
