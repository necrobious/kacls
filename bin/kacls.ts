#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { KaclsDomainStack } from '../lib/kacls-domain-stack';
import { KaclsApiStack } from '../lib/kacls-api-stack';
import { KaclsStack } from '../lib/kacls-stack';

const app = new cdk.App();

new KaclsDomainStack(app, 'KaclsDomainStack', {
  env:{region: 'us-east-1'}
});

// Cloudfront, ACM, and WAF usage all require us-east-1
new KaclsApiStack(app, 'KaclsApiStack', {
  env:{region: 'us-east-1'}
});


new KaclsStack(app, 'KaclsStack', {
  /* If you don't specify 'env', this stack will be environment-agnostic.
   * Account/Region-dependent features and context lookups will not work,
   * but a single synthesized template can be deployed anywhere. */

  /* Uncomment the next line to specialize this stack for the AWS Account
   * and Region that are implied by the current CLI configuration. */
  // env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },

  /* Uncomment the next line if you know exactly what Account and Region you
   * want to deploy the stack to. */
  // env: { account: '123456789012', region: 'us-east-1' },

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
});
