import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export class KaclsApiStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // get the path where our main lambda fuction has been compiled and zipped.
    const fn20230102Path = this.node.tryGetContext('kacls:lambda:v20230102:path');

    // get the Route53 PublicHostedZone's ID and name for kacls.com from the CloudFormation export, exported by the KaclsDomainStack(kacls-domain-stack.ts) stack
    const kaclsZoneId = cdk.Fn.importValue('KacklsDotComHostedZoneId'); 
    const kaclsZoneName = cdk.Fn.importValue('KacklsDotComHostedZoneName');

//--- Route53 Zone and api.kacls.com domain name
    const apiDomainName = `api.${kaclsZoneName}`;
    // build our kacls.com zone instance using the id
    const kaclsZone = route53.PublicHostedZone.fromHostedZoneAttributes(this, "KaclsDomainApiDomainZone", {
      hostedZoneId: kaclsZoneId,
      zoneName: kaclsZoneName,
    });

//--- KMS Encryption CMK
    // key.grant(lambdaExecRole, 'kms:GetPublicKey', 'kms:Sign', 'kms:UpdateKeyDescription', 'kms:DescribeKey');

//--- ACM Certificate for the api.kacls.com domain name
    // mint a domain certificate in ACM for the api.kacls.com domain, using DNS validation (via CAA, with amazon.com listed)
    const apiCert = new acm.Certificate(this, 'KaclsDomainApiCert', {
      domainName: apiDomainName,
      validation: acm.CertificateValidation.fromDns(kaclsZone),
    });

    new cdk.CfnOutput(this, "KaclsDomainApiCertArn", {
      value: apiCert.certificateArn,
      exportName: "KaclsDomainApiCertArn",
    });

//--- Api Gateway v2 API  
    const api = new apigwv2.CfnApi(this, 'KaclsApi', {
      name: 'kacls',
      description: 'the Key Access Control List Service',
      corsConfiguration: {
        allowCredentials: false,
        allowHeaders: ['*'],
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowOrigins: ['https://client-side-encryption.google.com'],
        exposeHeaders: [],// Google CSE spec does not use response headers, 
        maxAge: 600, // 10 min
      },
      protocolType: 'HTTP',
    });


    new cdk.CfnOutput(this, 'KaclsApiId', {
      value: api.attrApiId,
      exportName: 'KaclsApiId',
    });

    new cdk.CfnOutput(this, 'KaclsApiEndpoint', {
      value: api.attrApiEndpoint,
      exportName: 'KaclsApiEndpoint',
    });

//--- IAM Roles 
    const fn20230102ExecRole = new iam.Role(this,`KaclsApiFnV20230102ExecRole`, {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: `lambda execution role for the KACLS API Lambda Function, v20230102`,
    });     

    fn20230102ExecRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'));

//--- Lambda Functions
    // TODO: Replace with Rust function
    const fn20230102 = new lambda.Function(this, 'KaclsApiFnV20230102', {
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      tracing: lambda.Tracing.ACTIVE,
      timeout: cdk.Duration.seconds(60),
      runtime: lambda.Runtime.PROVIDED_AL2,
      handler: 'not.used', // name.othername pattern required, else will cause runtime cfn error with obscure error
      environment: {
        RUST_LOG: 'info',
      },
      role: fn20230102ExecRole,
      code: lambda.Code.fromAsset(fn20230102Path),
/*
      code: lambda.Code.fromInline(`
        exports.handler = async (event, context) => ({
          statusCode: 200,
          body: '{ "name": "kacls", "vendor_id": "kacls.com", "version": "20230102", "server_type": "KACLS", "event": ' + JSON.stringify(event) + '}',
        })
      `),
      handler: 'index.handler',
      runtime: lambda.Runtime.NODEJS_18_X,
*/
    });
    // can be called by apigateway
    fn20230102.grantInvoke(new iam.ServicePrincipal('apigateway.amazonaws.com'));

//--- Api Gateway v2 Integrations
    const region = process.env.CDK_DEPLOY_REGION || process.env.CDK_DEFAULT_REGION;
    const integration20230102 = new apigwv2.CfnIntegration(this, 'KaclsApiIntegrationV20230102', {
      apiId: api.attrApiId,
      integrationType: 'AWS_PROXY',
      connectionType: 'INTERNET', // INTERNET is the AWS default
      description: 'Implements the /status method of the Google Workspace Client-Side Encryption API, see: https://developers.google.com/workspace/cse/reference/status',
      integrationMethod: 'POST',
      integrationUri: `arn:aws:apigateway:${this.region}:lambda:path/2015-03-31/functions/${fn20230102.functionArn}/invocations`, 
      payloadFormatVersion: '2.0',
      timeoutInMillis: 30000, // Timeout should be between 50 ms and 30000 ms, 30 second in the AWS default. 
    });
    const integrationTarget = `integrations/${integration20230102.ref}`;

//--- Api Gateway v2 Routes (all routs lead to the same integration, but ensures a distinct RouteKey in the funciton's event)
    new apigwv2.CfnRoute(this, 'KaclsApiRouteTakeoutUnwrapV20230102', {
      apiId: api.attrApiId,
      routeKey: 'POST /v20230102/takeout_unwrap',
      authorizationType: 'NONE', // authz managed in the handler
      operationName: 'kacls:takeout_unwrap',
      target: integrationTarget,  
    });

    new apigwv2.CfnRoute(this, 'KaclsApiRouteRewrapV20230102', {
      apiId: api.attrApiId,
      routeKey: 'POST /v20230102/rewrap',
      authorizationType: 'NONE', // authz managed in the handler
      operationName: 'kacls:rewrap',
      target: integrationTarget,  
    });

    new apigwv2.CfnRoute(this, 'KaclsApiRouteUnwrapV20230102', {
      apiId: api.attrApiId,
      routeKey: 'POST /v20230102/unwrap',
      authorizationType: 'NONE', // authz managed in the handler
      operationName: 'kacls:unwrap',
      target: integrationTarget,  
    });

    new apigwv2.CfnRoute(this, 'KaclsApiRouteWrapV20230102', {
      apiId: api.attrApiId,
      routeKey: 'POST /v20230102/wrap',
      authorizationType: 'NONE', // authz managed in the handler
      operationName: 'kacls:wrap',
      target: integrationTarget,  
    });

    new apigwv2.CfnRoute(this, 'KaclsApiRouteDigestV20230102', {
      apiId: api.attrApiId,
      routeKey: 'POST /v20230102/digest',
      authorizationType: 'NONE', // authz managed in the handler
      operationName: 'kacls:digest',
      target: integrationTarget,  
    });

    new apigwv2.CfnRoute(this, 'KaclsApiRouteStatusV20230102', {
      apiId: api.attrApiId,
      routeKey: 'GET /v20230102/status',
      authorizationType: 'NONE', // authz managed in the handler
      operationName: 'kacls:status',
      target: integrationTarget,  
    });

//--- Api Gateway v2 Stages (just `prod` for now)
    const prodStage = new apigwv2.CfnStage(this, 'KaclsApiStageProd', {
      apiId: api.attrApiId,
      stageName: 'prod',
      description: 'production stage',
      autoDeploy: true,
    });

//--- CloudFront Functions
    const securityHeadersFn = new cloudfront.Function(this, 'KaclsApiFnSecurityHeaders', {
      code: cloudfront.FunctionCode.fromInline(`
        function handler(event) {
            var response = event.response;
            var headers = response.headers;

            headers['strict-transport-security'] = { value: 'max-age=63072000; includeSubdomains; preload'}; 
            headers['content-security-policy'] = { value: "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'"}; 
            headers['x-content-type-options'] = { value: 'nosniff'}; 
            headers['x-frame-options'] = {value: 'DENY'}; 
            headers['x-xss-protection'] = {value: '1; mode=block'}; 

            return response;
        }
      `),
    });

//--- CloudFront Behavior
    // api.attrApiEndpoint contains "https://{apiId}.execute-api.amazonaws.com", origins.HttpOrigin expects just the domain domain name.
    // api.attrApiEndpoint is a CFN Token, so we have to use CF intrinsic functions to slice off the 'https://' prefix.
    const originDomainName = cdk.Fn.select(1, cdk.Fn.split("https://", api.attrApiEndpoint));  

    const defaultBehavior = {
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      originRequestPolicy: cloudfront.OriginRequestPolicy.CORS_CUSTOM_ORIGIN,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      functionAssociations: [{
        eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE,
        function: securityHeadersFn,
      }],
      origin: new origins.HttpOrigin(originDomainName, {
        originPath: `/${prodStage.stageName}`,
        originSslProtocols:  [ cloudfront.OriginSslPolicy.TLS_V1_2 ],
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY
      }),
    };

//--- CloudFront Distribution
    const distribution = new cloudfront.Distribution(this, 'KaclsApiDistribution', {
      enabled: true,
      comment: "the KACLS API frontdoor",
      certificate: apiCert,
      domainNames: [apiDomainName],
      enableIpv6: true,
      defaultBehavior,
      geoRestriction: cloudfront.GeoRestriction.allowlist('US', 'GB'),
      httpVersion: cloudfront.HttpVersion.HTTP3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      sslSupportMethod: cloudfront.SSLMethod.SNI, // default
      enableLogging: false, // TODO: set log bucket inplace before turning on logging 
      //logBucket:          // TODO
      //logFilePrefix:
      //logIncludesCookies:
    });

    new cdk.CfnOutput(this, 'KaclsApiDistributionDomainName', {
      value: distribution.distributionDomainName,
      exportName: 'KaclsApiDistributionDomainName',
    });

    // add the api subdomain onto the kacls.com zone
    const apiCname = new route53.CnameRecord(this, 'KaclsDomainApiCname', {
      recordName: apiDomainName, // this domain's name 
      domainName: distribution.distributionDomainName, // set to CloudFront DistributionDomainName
      zone: kaclsZone,
    });

  }
}
