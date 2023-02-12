import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import { Construct } from 'constructs';
import { SSMParameterReader } from './ssm-parameter-reader';
import * as util from 'util';

export interface KaclsEncKeyStackProps extends cdk.StackProps {
  keyAdmins: iam.IPrincipal[]
}

/*
function defaultKeyPolicy(accountId: string, keyAdminArns: string[]): any {
  return [{
    "Sid": "Enable IAM User Permissions",
    "Effect": "Allow",
    "Principal": {
      "AWS": `arn:aws:iam::${accountId}:root`
    },
    "Action": "kms:*",
    "Resource": "*"
  },
  {
    "Sid": "Allow access for Key Administrators",
    "Effect": "Allow",
    "Principal": {
        "AWS": keyAdminArns
    },
    "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
    ],
    "Resource": "*"
  }];

}

function encryptionKeyCdkContextKey(account: string): string {
  return `kacls:account=${account}:primaryEncryptionKeyArn`;
}
*/
const KACLS_ENC_KEY_ARN_SSM_PARAM = 'KACLS_ENC_KEY_ARN_SSM_PARAM';

export class KaclsEncKeyStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: KaclsEncKeyStackProps) {
    super(scope, id, props);
//    const keyPolicy = defaultKeyPolicy(this.account, props.keyAdminArns);
    const keyPolicy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: 'Enable IAM User Permissions',
          actions: [
            'kms:*',
          ],
          principals: [new iam.AccountRootPrincipal()],
          resources: ['*'],
        }),
        new iam.PolicyStatement({
          actions: [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion",
           ],
          principals: props.keyAdmins,
          resources: ['*'],
        }),
      ],
    });
//    console.log(util.inspect(keyPolicy, {showHidden: false, depth: null, colors: true}));
    if (this.region === 'us-east-1') {
      const primaryKey = new kms.CfnKey(this, 'KaclsEncKey', {
        description: 'The primary KACLS encryption key',
        enableKeyRotation: true,
        multiRegion: true,
        enabled: true,
        keySpec: 'SYMMETRIC_DEFAULT',
        keyUsage: 'ENCRYPT_DECRYPT',
        keyPolicy,
        pendingWindowInDays: 30,
      });
      new ssm.StringParameter(this, 'KaclsEncKeyArnSSMParam', {
        parameterName: KACLS_ENC_KEY_ARN_SSM_PARAM,
        description: 'The primary KACLS encryption key',
        stringValue: primaryKey.attrArn
      });
      new cdk.CfnOutput(this, "KaclsEncKeyArn", {
        value: primaryKey.attrArn,
        exportName: "KaclsEncKeyArn",
      });
    }
    else {
      const primaryKeyArnReader = new SSMParameterReader(this, 'KaclsEncKeyArnReader', {
        parameterName: KACLS_ENC_KEY_ARN_SSM_PARAM,
        region: 'us-east-1'
      });

      const primaryKeyArn: string  = primaryKeyArnReader.getParameterValue();

      const key = new kms.CfnReplicaKey(this, "KaclsEncKey", {
        keyPolicy,
        primaryKeyArn,
        description: "The KACLS encryption key",
        enabled: true,
        pendingWindowInDays: 30,
      });

      new cdk.CfnOutput(this, "KaclsEncKeyArn", {
        value: key.attrArn,
        exportName: "KaclsEncKeyArn",
      });
    }
  }
}
