import * as cdk from 'aws-cdk-lib';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import { SSMParameterReader } from './ssm-parameter-reader';

const KACLS_WAF_WEB_ACL_ARN_SSM_PARAM = 'KACLS_WAF_WEB_ACL_ARN_SSM_PARAM';

const AWS_COMMON_RULES_SET: wafv2.CfnWebACL.ManagedRuleGroupStatementProperty = {
  vendorName: 'AWS',
  name: 'AWSManagedRulesCommonRuleSet',
};

// inspired from: https://github.com/cdk-patterns/serverless/blob/main/the-waf-apigateway/typescript/lib/the-waf-stack.ts

export class KaclsWafStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 0 AWS Common Rule Set
    const awsCommonRuleSet: wafv2.CfnWebACL.RuleProperty = {
      name: 'AWS-AWSManagedRulesCommonRuleSet',
      priority: 0,
      overrideAction: {
        count: {}
        // none: {}
      },
      statement: {
        managedRuleGroupStatement: {
          name: 'AWSManagedRulesCommonRuleSet',
          vendorName: 'AWS',
          excludedRules: [
            {name: 'SizeRestrictions_BODY'},
          ]
        }
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'kacls-waf-crs',
        sampledRequestsEnabled: true
      }
    };

    // 10 AWS AnonIPAddress
    const awsAnonIPList: wafv2.CfnWebACL.RuleProperty = {
      name: 'awsAnonymousIP',
      priority: 10,
      overrideAction: {
        count: {}
        // none: {}
      },
      statement: {
        managedRuleGroupStatement: {
          name: 'AWSManagedRulesAnonymousIpList',
          vendorName: 'AWS',
          excludedRules: []
        }
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'kacls-waf-ip-anon',
        sampledRequestsEnabled: true
      }
    };

    // 20 AWS ip reputation List
    const awsIPRepList: wafv2.CfnWebACL.RuleProperty = {
      name: 'awsIPReputation',
      priority: 20,
      overrideAction: {
        count: {}
        // none: {}
      },
      statement: {
        managedRuleGroupStatement: {
          name: 'AWSManagedRulesAmazonIpReputationList',
          vendorName: 'AWS',
          excludedRules: []
        }
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'kacls-waf-ip-rep',
        sampledRequestsEnabled: true
      }
    };


    const webAcl =  new wafv2.CfnWebACL(this, 'KaclsWebACL', {
      name: 'KaclsWebACL',
      description: 'The KACLS Web ACL',
      scope: 'REGIONAL', // Because we are attaching to an ALB, CLOUDFRONT if attacking to CloudFront
      defaultAction: {
        allow: {},
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true, // whether the associated resource sends metrics to Amazon CloudWatch.
        metricName: 'kacls-waf', // A name of the Amazon CloudWatch metric dimension.
        sampledRequestsEnabled: false, // whether AWS WAF should store a sampling of the web requests that match the rules.
      },
      rules: [
        awsCommonRuleSet,
        awsAnonIPList,
        awsIPRepList,
      ],
    });

    new cdk.CfnOutput(this, "KaclsWebACLArn", {
      value: webAcl.attrArn,
      exportName: "KaclsWebACLArn",
    });
  }
}
