import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as route53 from 'aws-cdk-lib/aws-route53';

export class KaclsDomainStack extends cdk.Stack {
  zone: route53.PublicHostedZone

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    this.zone = new route53.PublicHostedZone(this, "KacklsDotComDomainZone", {
      zoneName: 'kacls.com',
      caaAmazon: true,
    }); 

    new cdk.CfnOutput(this, "KacklsDotComHostedZoneId", {
      value: this.zone.hostedZoneId,
      exportName: "KacklsDotComHostedZoneId",
    });

    new cdk.CfnOutput(this, "KacklsDotComHostedZoneArn", {
      value: this.zone.hostedZoneArn,
      exportName: "KacklsDotComHostedZoneArn",
    });

    new cdk.CfnOutput(this, "KacklsDotComHostedZoneName", {
      value: this.zone.zoneName,
      exportName: "KacklsDotComHostedZoneName",
    });
  }
}
