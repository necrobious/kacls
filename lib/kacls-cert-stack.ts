import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
//import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import { Construct } from 'constructs';

export class KaclsCertStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // get the Route53 PublicHostedZone's ID and name for kacls.com from the CloudFormation export, exported by the KaclsDomainStack(kacls-domain-stack.ts) stack
    const kaclsZoneId = cdk.Fn.importValue('KacklsDotComHostedZoneId'); 
    const kaclsZoneName = cdk.Fn.importValue('KacklsDotComHostedZoneName');

//--- Route53 Zone and api.kacls.com domain name
    const apiDomainName = `api.${kaclsZoneName}`;
    const lb1DomainName = `lb-1.${this.region}.api.${kaclsZoneName}`;

    // build our kacls.com zone instance using the id
    const kaclsZone = route53.PublicHostedZone.fromHostedZoneAttributes(this, "KaclsDomainCertDomainZone", {
      hostedZoneId: kaclsZoneId,
      zoneName: kaclsZoneName,
    });

    const lb1Cert = new acm.Certificate(this, 'KaclsDomainLB1Cert', {
      domainName: lb1DomainName,
      subjectAlternativeNames: [apiDomainName],
      validation: acm.CertificateValidation.fromDns(kaclsZone),
    });

    new cdk.CfnOutput(this, "KaclsDomainLB1CertArn", {
      value: lb1Cert.certificateArn,
      exportName: "KaclsDomainLB1CertArn",
    });
  }
}
