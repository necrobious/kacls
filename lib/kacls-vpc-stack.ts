import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';

import { Construct } from 'constructs';

export class KaclsVpcStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    let cidr: string 
    if (this.region === 'us-east-1') {
      cidr = '10.254.254.192/26'
    } else if (this.region === 'us-west-2') {
      cidr = '10.254.253.192/26'
    } else {
      throw new Error(`Unknow region ${this.region}`);
    }

    const vpc1 = new ec2.Vpc(this, "KaclsVpc1", {
      ipAddresses: ec2.IpAddresses.cidr(cidr),
      vpcName: 'KaclsVpc1',
      subnetConfiguration: [
        {
          cidrMask: 28,
          name: 'Ingress',
          subnetType: ec2.SubnetType.PUBLIC,
        }
      ]
    });

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
