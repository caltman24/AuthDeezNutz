# Cookie Authentication with Remix + .NET API
This branch demonstrates Cookie authentication between Remix and a .NET Api using Identity Framework and external identity providers like google.

This setup is much much simpler than the JWT authentication setup. But probably a bit more of a headache than using the bearer tokens since we are manging sessions with
both remix and the .net server

Go with JWTS if
- You have microservices architecture where authentication is validated across multiple services
- You want truly stateless authentication where no server-side session storage is needed
- You have Cross-domain API access where cookies face CORS limitations
- You need to embed authorization data directly in the token

