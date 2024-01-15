import { decode, verify } from 'jsonwebtoken';
import { default as jwkToPem } from 'jwk-to-pem';
import { default as axios } from 'axios';

// types
import { Handler } from 'aws-lambda';

/**
 * env variables needed
 * - RESOURCE_ARN: Api-Gateway arn with path to the resouce that you want to protect with this authorizer
 *   e.g. arn:aws:execute-api:us-west-2:1234567890:abcdefg/prod/* will allow access to all routes behind the prod stage
 * - AUDIENCE: iOS app name e.g. com.example.my-app
 */

// TODO: improve types
export const handler: Handler = async (event: any, context: any, callback: any) => {

    const bearerStr: string = event.authorizationToken;
    const bearerToken: string = bearerStr.split(' ')[1];

    const decodedToken = decode(bearerToken, { complete: true });
    const payload = decodedToken?.payload as { [key: string]: string | number | boolean };

    const kid = decodedToken?.header.kid;

    if (kid === undefined) {
        callback("Unauthorized");
        return;
    }

    const { data: applePubJwks } = await axios.get('https://appleid.apple.com/auth/keys');

    const filteredKeys = applePubJwks.keys.filter((k: any) => k.kid === kid);
    if (filteredKeys.length !== 1) {
        throw new Error('Key not found');
    }

    const pem = jwkToPem(filteredKeys[0])

    try {
        verify(bearerToken, pem, {
            audience: process.env.AUDIENCE,
            issuer: 'https://appleid.apple.com',
            ignoreExpiration: false
        });
    } catch (e) {
        console.error(e);
        callback("Unauthorized");
        return;
    }

    const authResponse = generatePolicy(payload.sub as string, 'Allow', event.methodArn);
    authResponse.context = { email: payload.email };
    callback(null, authResponse);

}

var generatePolicy = function(principalId: string, effect: string, resource: string) {
    var authResponse: any = {};
    
    // TODO: create objects for all of these (or import aws types)
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument: any = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statement: any = {};
        statement.Action = 'execute-api:Invoke'; 
        statement.Effect = effect;
        statement.Resource = process.env.ALLOW_RESOURCE_ARN;
        policyDocument.Statement[0] = statement;
        authResponse.policyDocument = policyDocument;
    }
    
    return authResponse;
}