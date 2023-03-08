import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import { Construct } from 'constructs';

export class KaclsApiStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // get the path where our main lambda fuction has been compiled and zipped.
    const fn20230102Path = this.node.tryGetContext("kacls:lambda:v20230102:path");

//--- ALB Security Group 
    const albSecurityGroupId = cdk.Fn.importValue("KaclsAlb1SecurityGroupId"); 
    const albSecurityGroup = ec2.SecurityGroup.fromSecurityGroupId(this, "KaclsAlbSecurityGroup", albSecurityGroupId);

//--- ALB Listener 
    const albListenerArn = cdk.Fn.importValue("KaclsAlb1ListenerArn"); 
    const albListener = elbv2.ApplicationListener.fromApplicationListenerAttributes(this, "AlbTLSListener", {
      listenerArn: albListenerArn,
      securityGroup: albSecurityGroup,
    });

//--- KMS Encryption Key
    const kmsEncKeyArn = cdk.Fn.importValue("KaclsEncKeyArn"); 
    const kmsEncKey = kms.Key.fromKeyArn(this, "KaclsEncKey", kmsEncKeyArn);
    const kmsEncKeyArns = JSON.stringify([
      kmsEncKeyArn
    ]);

//--- IAM Roles 
    const fn20230102ExecRole = new iam.Role(this,"KaclsApiFnV20230102ExecRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "lambda execution role for the KACLS API Lambda Function, v20230102",
    });     
    fn20230102ExecRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"));
    kmsEncKey.grantEncryptDecrypt(fn20230102ExecRole);

//--- Lambda Functions
    const fn20230102 = new lambda.Function(this, "KaclsApiFnV20230102", {
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      tracing: lambda.Tracing.ACTIVE,
      timeout: cdk.Duration.seconds(60),
      runtime: lambda.Runtime.PROVIDED_AL2,
      handler: "not.used", // name.othername pattern required, else will cause runtime cfn error with obscure error
      environment: {
        KACLS_ENC_KEY_ARNS: kmsEncKeyArns,
        RUST_LOG: "info",
        RUST_BACKTRACE: "full",
      },
      logRetention: logs.RetentionDays.ONE_WEEK,
      role: fn20230102ExecRole,
      code: lambda.Code.fromAsset(fn20230102Path),
    });

    fn20230102.grantInvoke(new iam.ServicePrincipal("elasticloadbalancing.amazonaws.com"));

    const v20230102TargetGroup = new elbv2.ApplicationTargetGroup(this, "v20230102 Lambda Handler", {
      targets: [new targets.LambdaTarget(fn20230102)],
      healthCheck: {
        healthyHttpCodes: "204",
        path: "/healthcheck",
        enabled: true,
        interval: cdk.Duration.seconds(60),
      }
    });

    albListener.addTargetGroups("v20230102 Lambda Handler", {
      targetGroups: [v20230102TargetGroup],
      conditions: [
        elbv2.ListenerCondition.pathPatterns([
          "/healthcheck",
          "/v20230102/*"
        ])
      ],
      priority: 1,
    });

  }
}
