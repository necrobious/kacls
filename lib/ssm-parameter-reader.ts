// see: https://stackoverflow.com/questions/59774627/cloudformation-cross-region-reference
// ported to CDKv2
import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';

export interface SSMParameterReaderProps {
  parameterName: string;
  region: string;
}

export class SSMParameterReader extends cr.AwsCustomResource {
  constructor(scope: Construct, name: string, props: SSMParameterReaderProps) {
    const { parameterName, region } = props;

    const ssmGetAwsSdkCall: cr.AwsSdkCall = {
      service: 'SSM',
      action: 'getParameter',
      parameters: {
        Name: parameterName
      },
      region,
      physicalResourceId: cr.PhysicalResourceId.of(Date.now().toString()), // Update physical id to always fetch the latest version
    };

    const ssmDelAwsSdkCall: cr.AwsSdkCall = {
      service: 'SSM',
      action: 'deleteParameter',
      parameters: {
        Name: parameterName
      },
      region,
    };

    super(scope, name, { 
      onCreate: ssmGetAwsSdkCall,
      onUpdate: ssmGetAwsSdkCall,
      onDelete: ssmDelAwsSdkCall,
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
        resources: cr.AwsCustomResourcePolicy.ANY_RESOURCE,
      }),
    });
  }

  public getParameterValue(): string {
    return this.getResponseField('Parameter.Value').toString();
  }
}
