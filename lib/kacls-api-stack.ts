import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as r53targets from 'aws-cdk-lib/aws-route53-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import { Construct } from 'constructs';

export class KaclsApiStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // get the path where our main lambda fuction has been compiled and zipped.
    const fn20230102Path = this.node.tryGetContext('kacls:lambda:v20230102:path');

    // get the VPC
    const vpc1 = ec2.Vpc.fromLookup(this, 'KaclsVpc1', {
      vpcName: 'KaclsVpc1',
      region: this.region,
    });

//--- Route53 Zone and api.kacls.com domain name
    // get the Route53 PublicHostedZone's ID and name for kacls.com from the CloudFormation export, exported by the KaclsDomainStack(kacls-domain-stack.ts) stack
    const kaclsZoneId = cdk.Fn.importValue('KacklsDotComHostedZoneId'); 
    const kaclsZoneName = cdk.Fn.importValue('KacklsDotComHostedZoneName');
    const apiDomainName = `api.${kaclsZoneName}`;
    const lb1DomainName = `lb-1.${this.region}.api.${kaclsZoneName}`;

    // build our kacls.com zone instance using the id
    const kaclsZone = route53.PublicHostedZone.fromHostedZoneAttributes(this, "KaclsDomainApiDomainZone", {
      hostedZoneId: kaclsZoneId,
      zoneName: kaclsZoneName,
    });

//--- ACM Certificate for the api.kacls.com domain name
    const lb1CertArn = cdk.Fn.importValue('KaclsDomainLB1CertArn'); 
    const lb1Cert = acm.Certificate.fromCertificateArn(this, 'KaclsDomainLB1Cert', lb1CertArn); 

//--- KMS Encryption Key
    const kmsEncKeyArn = cdk.Fn.importValue('KaclsEncKeyArn'); 
    const kmsEncKey = kms.Key.fromKeyArn(this, 'KaclsEncKey', kmsEncKeyArn);

//--- IAM Roles 
    const fn20230102ExecRole = new iam.Role(this,`KaclsApiFnV20230102ExecRole`, {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: `lambda execution role for the KACLS API Lambda Function, v20230102`,
    });     
    fn20230102ExecRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'));
    kmsEncKey.grantEncryptDecrypt(fn20230102ExecRole);

//--- Lambda Functions
    const fn20230102 = new lambda.Function(this, 'KaclsApiFnV20230102', {
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      tracing: lambda.Tracing.ACTIVE,
      timeout: cdk.Duration.seconds(60),
      runtime: lambda.Runtime.PROVIDED_AL2,
      handler: 'not.used', // name.othername pattern required, else will cause runtime cfn error with obscure error
      environment: {
        KACLS_ENC_KEY_ARN: kmsEncKeyArn,
        RUST_LOG: 'info',
        RUST_BACKTRACE: 'full',
      },
      logRetention: logs.RetentionDays.ONE_WEEK,
      role: fn20230102ExecRole,
      code: lambda.Code.fromAsset(fn20230102Path),
    });

    fn20230102.grantInvoke(new iam.ServicePrincipal('elasticloadbalancing.amazonaws.com'));

    const lb1LogsAccessBucket = new s3.Bucket(this, 'KaclsAlb1AccessLogsBucket', {
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [
        {
          enabled: true,
          expiration: cdk.Duration.days(7),
        }
      ]
    });

    const lb1 = new elbv2.ApplicationLoadBalancer(this, "KaclsAlb1", {
      vpc: vpc1,
      internetFacing: true,
    });

    lb1.logAccessLogs(lb1LogsAccessBucket);

    const listener = lb1.addListener('TLS Listener', {
      port: 443,
      sslPolicy: elbv2.SslPolicy.FORWARD_SECRECY_TLS12_RES_GCM,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      certificates: [ lb1Cert ],
      open: true,
    });

    // TODO: investigate breking ot the ALB into it's own stack, with ith the API stack locating the listener and appending Lambda targets to it

    const targetGroup = listener.addTargets('v20230102 Lambda Target', {
      targets: [new targets.LambdaTarget(fn20230102)],
      healthCheck: {
        healthyHttpCodes: "204",
        path: "/healthcheck",
        enabled: true,
        interval: cdk.Duration.seconds(60),
      }
    });

    // add load banancer 1's subdomain onto the kacls.com zone
    const lb1Cname = new route53.CnameRecord(this, 'KaclsDomainLB1Cname', {
      recordName: lb1DomainName,
      domainName: lb1.loadBalancerDnsName,
      zone: kaclsZone,
    });

    // TODO: Investigate Route53 healthchecks via CloudWatch Alarms:
    //       see: https://medium.com/dazn-tech/how-to-implement-the-perfect-failover-strategy-using-amazon-route53-1cc4b19fa9c7

    // add the api subdomain onto the kacls.com zone
    const apiARecord = new route53.ARecord(this, 'KaclsDomainApiARecord', {
      recordName: apiDomainName,
      target: route53.RecordTarget.fromAlias(new r53targets.LoadBalancerTarget(lb1)),
      zone: kaclsZone,
    });

    // workaround to test latency routing policy, L2 constructs dont provide a way to do this directly
    // see: https://github.com/aws/aws-cdk/issues/4391
    const apiRecordSet = (apiARecord.node.defaultChild as route53.CfnRecordSet);
    apiRecordSet.region = this.region;
    apiRecordSet.setIdentifier = this.region;

  }
}
