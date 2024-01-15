import { handler } from '../authorizer';
import { Context } from 'aws-lambda';

import { decode, verify } from 'jsonwebtoken';
jest.mock('jsonwebtoken');

import { default as jwkToPem } from 'jwk-to-pem';
jest.mock('jwk-to-pem');

import { default as axios } from 'axios';
jest.mock('axios');

const mockDecode = jest.mocked(decode);
const mockVerify = jest.mocked(verify);
const mockJwkToPem = jest.mocked(jwkToPem);
const mockAxios = jest.mocked(axios);

describe('appleAuthorize', () => {

    const apiGatewayEvent = {
        authorizationToken: 'Bearer abcdefghijklmnop',
        methodArn: 'arn:abcdefg'
    }

    const decodedToken = {
        header: {
            kid: 'testKid'
        },
        payload: {
            sub: 'testSub',
            email: 'testEmail'
        }
    }

    beforeEach(() => {

        jest.clearAllMocks();

        process.env.ALLOW_RESOURCE_ARN = 'arn:test-resource';
        process.env.AUDIENCE = 'com.example.unittest';

        mockDecode.mockReturnValue(decodedToken);
        mockJwkToPem.mockReturnValue('testPem');
        mockAxios.get.mockReturnValue(Promise.resolve({
            data: {
                keys: [
                    {
                        kid: 'testKid',
                        otherKey: 'otherValue'
                    }
                ]
            }
        }));
    });

    describe('successful behavior', () => {

        it('correct callback called on success', async () => {
            const callback = jest.fn();
            await handler(apiGatewayEvent, {} as Context, callback);

            expect(callback).toHaveBeenCalledTimes(1);
            expect(callback).toHaveBeenCalledWith(null, {
                "context": {
                    "email": "testEmail",
                },
                "policyDocument": {
                    "Statement": [
                        {
                            "Action": "execute-api:Invoke",
                            "Effect": "Allow",
                            "Resource": "arn:test-resource",
                        },
                    ],
                    "Version": "2012-10-17",
                },
                "principalId": "testSub",
            });
        });

        it('provides correct arguments to decode', async () => {
            await handler(apiGatewayEvent, {} as Context, jest.fn());

            expect(decode).toHaveBeenCalledTimes(1);
            expect(decode).toHaveBeenCalledWith('abcdefghijklmnop', { complete: true });
        });

        it('calls correct apple key endpoint', async () => {
            await handler(apiGatewayEvent, {} as Context, jest.fn());

            expect(mockAxios.get).toHaveBeenCalledTimes(1);
            expect(mockAxios.get).toHaveBeenCalledWith('https://appleid.apple.com/auth/keys');
        });

        it('calls jwkToPem with correct key', async () => {
            await handler(apiGatewayEvent, {} as Context, jest.fn());

            expect(mockJwkToPem).toHaveBeenCalledTimes(1);
            expect(mockJwkToPem).toHaveBeenCalledWith({
                kid: 'testKid',
                otherKey: 'otherValue'
            });
        });

        it('calls verify with correct arguments', async () => {
            await handler(apiGatewayEvent, {} as Context, jest.fn());

            expect(verify).toHaveBeenCalledTimes(1);
            expect(verify).toHaveBeenCalledWith('abcdefghijklmnop', 'testPem', {
                audience: 'com.example.unittest',
                issuer: 'https://appleid.apple.com',
                ignoreExpiration: false
            });
        });

    });

    describe('unauthorized', () => {

        it('missing kid throws unauthorized error', async () => {
            const callback = jest.fn();

            mockDecode.mockReturnValue({
                ...decodedToken,
                header: {}
            });

            await handler(apiGatewayEvent, {} as Context, callback);

            expect(callback).toHaveBeenCalledTimes(1);
            expect(callback).toHaveBeenCalledWith('Unauthorized');

            // ensure we haven't gotten to the axios call
            expect(mockAxios.get).toHaveBeenCalledTimes(0);
        });

        it('verify throws error returns unauthorized', async () => {
            const callback = jest.fn();

            mockVerify.mockImplementation(() => { throw new Error() });

            await handler(apiGatewayEvent, {} as Context, callback);

            expect(callback).toHaveBeenCalledTimes(1);
            expect(callback).toHaveBeenCalledWith('Unauthorized');

            // ensure we called unauth in the right place
            expect(mockAxios.get).toHaveBeenCalledTimes(1);
        });

    });

    describe('failure scenarios', () => {

        it('apple keys unsuccessfully retrieved throws error', async () => {
            mockDecode.mockReturnValue({
                ...decodedToken,
                header: { kid: 'testInvalid' }
            });

            try {
                await handler(apiGatewayEvent, {} as Context, jest.fn());
                fail();
            } catch (e) {
                expect((e as Error).message).toEqual('Key not found');
            }
        });

    });

});