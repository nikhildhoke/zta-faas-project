# Zero Trust AWS Lambda with OPA

Zero Trust Authorisation for AWS Lambda Using OPA

This project implements a Zero Trust Architecture (ZTA) model for AWS Lambda by enforcing explicit, per-invocation authorisation.
Instead of relying only on API Gateway for authentication, every Lambda invocation performs:

JWT verification using Amazon Cognito

Claim validation inside the function

Open Policy Agent (OPA) policy evaluation

Allow/Deny decision per request

A separate Baseline path (public Lambda Function URL) is implemented for comparison.
