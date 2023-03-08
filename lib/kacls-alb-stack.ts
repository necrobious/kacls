import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as r53targets from 'aws-cdk-lib/aws-route53-targets';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

export class KaclsAlbStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // get the VPC
    const vpc1 = ec2.Vpc.fromLookup(this, "KaclsVpc1", {
      vpcName: "KaclsVpc1",
      region: this.region,
    });

//--- Route53 Zone and api.kacls.com domain name
    // get the Route53 PublicHostedZone's ID and name for kacls.com from the CloudFormation export, exported by the KaclsDomainStack(kacls-domain-stack.ts) stack
    const kaclsZoneId = cdk.Fn.importValue("KacklsDotComHostedZoneId"); 
    const kaclsZoneName = cdk.Fn.importValue("KacklsDotComHostedZoneName");
    const apiDomainName = `api.${kaclsZoneName}`;
    const lb1DomainName = `lb-1.${this.region}.api.${kaclsZoneName}`;

    // build our kacls.com zone instance using the id
    const kaclsZone = route53.PublicHostedZone.fromHostedZoneAttributes(this, "KaclsDomainApiDomainZone", {
      hostedZoneId: kaclsZoneId,
      zoneName: kaclsZoneName,
    });

//--- ACM Certificate for the api.kacls.com domain name
    const lb1CertArn = cdk.Fn.importValue("KaclsDomainLB1CertArn"); 
    const lb1Cert = acm.Certificate.fromCertificateArn(this, "KaclsDomainLB1Cert", lb1CertArn); 

//--- WAFv2
    const webAclArn = cdk.Fn.importValue("KaclsWebACLArn"); 

//--- load balancer s3 logging
    const lb1LogsAccessBucket = new s3.Bucket(this, "KaclsAlb1AccessLogsBucket", {
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

//--- load balancer security group
    const lb1SecurityGroup = new ec2.SecurityGroup(this, "KaclsAlb1SecurityGroup", {
        vpc: vpc1,
        allowAllOutbound: false,
    });

    new cdk.CfnOutput(this, "KaclsAlb1SecurityGroupId", {
      value: lb1SecurityGroup.securityGroupId,
      exportName: "KaclsAlb1SecurityGroupId",
    });

//--- load balancer
    const lb1 = new elbv2.ApplicationLoadBalancer(this, "KaclsAlb1", {
      vpc: vpc1,
      internetFacing: true,
      securityGroup: lb1SecurityGroup,
    });

    lb1.logAccessLogs(lb1LogsAccessBucket, "kacls-alb");

    const listener = lb1.addListener("TLSListener", {
      port: 443,
      sslPolicy: elbv2.SslPolicy.FORWARD_SECRECY_TLS12_RES_GCM,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      certificates: [ lb1Cert ],
      open: true,
      defaultAction: elbv2.ListenerAction.fixedResponse(403, {
        contentType: "application/json",
        messageBody: '{"code": 403,"message":"Unknown route","details":"Unknown route"}',
      })

    });

    new cdk.CfnOutput(this, "KaclsAlb1ListenerArn", {
      value: listener.listenerArn,
      exportName: "KaclsAlb1ListenerArn",
    });

    // add load banancer 1's subdomain onto the kacls.com zone
    const lb1Cname = new route53.CnameRecord(this, "KaclsDomainLB1Cname", {
      recordName: lb1DomainName,
      domainName: lb1.loadBalancerDnsName,
      zone: kaclsZone,
    });

    // TODO: Investigate Route53 healthchecks via CloudWatch Alarms:
    //       see: https://medium.com/dazn-tech/how-to-implement-the-perfect-failover-strategy-using-amazon-route53-1cc4b19fa9c7

    // add the api subdomain onto the kacls.com zone
    const apiARecord = new route53.ARecord(this, "KaclsDomainApiARecord", {
      recordName: apiDomainName,
      target: route53.RecordTarget.fromAlias(new r53targets.LoadBalancerTarget(lb1)),
      zone: kaclsZone,
    });

    // workaround to test latency routing policy, L2 constructs dont provide a way to do this directly
    // see: https://github.com/aws/aws-cdk/issues/4391
    const apiRecordSet = (apiARecord.node.defaultChild as route53.CfnRecordSet);
    apiRecordSet.region = this.region;
    apiRecordSet.setIdentifier = this.region;


    // wire AWSWAF WebACL into the LoadBalancer
    const webAclAssoc = new wafv2.CfnWebACLAssociation(this, "KaclsAlb1WebACLAssociation", {
      resourceArn: lb1.loadBalancerArn,
      webAclArn: webAclArn,
    });
  }
}
