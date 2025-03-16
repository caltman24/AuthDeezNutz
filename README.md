# Jwt authentication with Remix + .NET API
This branch demonstrates JWT authentication between Remix and a .NET Api using Identity Framework and external identity providers like google

This approach works but jwts aren't necessary for this use case. Since the remix app is a first party app, the opaque bearer tokens are fine.
JWTs encode and verify (via signing) their own claims. This allows the server to issue short-lived JWTs. They do not need to hit the DB. This reduces DB calls, and the refresh tokens are the only thing hitting the db from the jwt service

JWTs shine in distributed systems where any service can verify the token using a public key or shared secret without hitting a central server. If your API doesn’t need this (e.g., it’s a monolith or all requests hit a single auth server anyway), the stateless advantage of JWTs is moot, and opaque tokens are simpler to manage.
