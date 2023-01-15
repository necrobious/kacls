import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';

import { Construct } from 'constructs';

export class KaclsVpcStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    const vpc1 = new ec2.Vpc(this, "KaclsVpc1", {
      ipAddresses: ec2.IpAddresses.cidr('10.254.254.192/26'),
      vpcName: 'KaclsVpc1',
      subnetConfiguration: [
        {
          cidrMask: 28,
          name: 'Ingress',
          subnetType: ec2.SubnetType.PUBLIC,
        }
      ]

    });
/*
const lambdaFunction = new lambda.Function(this, 'KaclsAlbFn', {
  code: new lambda.InlineCode(`
exports.handler = async (event, context) => {
  console.log(event);
  return {
    statusCode:200,
    headers: {
      "Content-Type": "text/html"
    },
    body: "Request IP: " + event.headers["x-forwarded-for"]
  };
}
  `),
  handler: 'index.handler',
  runtime: lambda.Runtime.NODEJS_14_X,
});
*/

/*
const lb = new elbv2.ApplicationLoadBalancer(this, "KaclsAlb", {
  vpc: vpc1,
  internetFacing: true,
});
const listener = lb.addListener('Listener', {
  port: 80,
  open:true,// TBD
});
listener.addTargets('LambdaTargets', {
  targets: [new targets.LambdaTarget(lambdaFunction)],

  // For Lambda Targets, you need to explicitly enable health checks if you
  // want them.
  healthCheck: {
    enabled: true,
  }
});

    new cdk.CfnOutput(this, "KaclsLoadBalancerDnsName", {
      value: lb.loadBalancerDnsName,
      exportName: "KaclsLoadBalancerDnsName",
    });

    new cdk.CfnOutput(this, "KaclsLoadBalancerArn", {
      value: lb.loadBalancerArn,
      exportName: "KaclsLoadBalancerArn",
    });
*/

    new cdk.CfnOutput(this, "KaclsVpc1Id", {
      value: vpc1.vpcId,
      exportName: "KaclsVpc1Id",
    });
    new cdk.CfnOutput(this, "KaclsVpc1Arn", {
      value: vpc1.vpcArn,
      exportName: "KaclsVpc1Arn",
    });
  }
}
