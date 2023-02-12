import * as cdk from 'aws-cdk-lib';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import { SSMParameterReader } from './ssm-parameter-reader';

const KACLS_DOMAIN_INFO_HOSTED_ZONE_ID_SSM_PARAM = 'KACLS_DOMAIN_INFO_HOSTED_ZONE_ID_SSM_PARAM';
const KACLS_DOMAIN_INFO_HOSTED_ZONE_ARN_SSM_PARAM = 'KACLS_DOMAIN_INFO_HOSTED_ZONE_ARN_SSM_PARAM';
const KACLS_DOMAIN_INFO_ZONE_NAME_SSM_PARAM = 'KACLS_DOMAIN_INFO_ZONE_NAME_SSM_PARAM';

interface DomainInfo {
  hostedZoneId: string
  hostedZoneArn: string
  zoneName: string
};

export class KaclsDomainStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    let domainInfo: DomainInfo;
    if (this.region === 'us-east-1') {
      const zone = new route53.PublicHostedZone(this, "KacklsDotComDomainZone", {
        zoneName: 'kacls.com',
        caaAmazon: true,
      }); 

      new ssm.StringParameter(this, 'KacklsDotComDomainInfoHostedZoneIdSSMParam', {
        parameterName: KACLS_DOMAIN_INFO_HOSTED_ZONE_ID_SSM_PARAM,
        description: 'The KACLS domain hosted zone ID',
        stringValue: zone.hostedZoneId, 
      });

      new ssm.StringParameter(this, 'KacklsDotComDomainInfoHostedZoneArnSSMParam', {
        parameterName: KACLS_DOMAIN_INFO_HOSTED_ZONE_ARN_SSM_PARAM,
        description: 'The KACLS domain hosted zone ARN',
        stringValue: zone.hostedZoneArn, 
      });

      new ssm.StringParameter(this, 'KacklsDotComDomainInfoZoneNameSSMParam', {
        parameterName: KACLS_DOMAIN_INFO_ZONE_NAME_SSM_PARAM,
        description: 'The KACLS domain info zone name',
        stringValue: zone.zoneName, 
      });

      domainInfo = {
        hostedZoneId: zone.hostedZoneId,
        hostedZoneArn: zone.hostedZoneArn,
        zoneName: zone.zoneName,
      };
    }
    else {
      const domainInfoHostedZoneIdReader = new SSMParameterReader(this, 'KacklsDotComDomainInfoHostedZoneIdReader', {
        parameterName: KACLS_DOMAIN_INFO_HOSTED_ZONE_ID_SSM_PARAM,
        region: 'us-east-1'
      });

      const domainInfoHostedZoneArnReader = new SSMParameterReader(this, 'KacklsDotComDomainInfoHostedZoneArnReader', {
        parameterName: KACLS_DOMAIN_INFO_HOSTED_ZONE_ARN_SSM_PARAM,
        region: 'us-east-1'
      });

      const domainInfoZoneNameReader = new SSMParameterReader(this, 'KacklsDotComDomainInfoZoneNameReader', {
        parameterName: KACLS_DOMAIN_INFO_ZONE_NAME_SSM_PARAM,
        region: 'us-east-1'
      });

      domainInfo = {
        hostedZoneId: domainInfoHostedZoneIdReader.getParameterValue(),
        hostedZoneArn: domainInfoHostedZoneArnReader.getParameterValue(),
        zoneName: domainInfoZoneNameReader.getParameterValue(),
      };
    }

    new cdk.CfnOutput(this, "KacklsDotComHostedZoneId", {
      value: domainInfo.hostedZoneId,
      exportName: "KacklsDotComHostedZoneId",
    });

    new cdk.CfnOutput(this, "KacklsDotComHostedZoneArn", {
      value: domainInfo.hostedZoneArn,
      exportName: "KacklsDotComHostedZoneArn",
    });

    new cdk.CfnOutput(this, "KacklsDotComHostedZoneName", {
      value: domainInfo.zoneName,
      exportName: "KacklsDotComHostedZoneName",
    });
  }
}
