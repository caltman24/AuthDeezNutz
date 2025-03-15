# AuthDeezNutz
This branch demonstrates Cookie authentication between Remix and a .NET Api using Identity Framework and external identity providers like google.

This setup is much much simpler than the JWT authentication setup. This should be the goto unless:

- You have microservices architecture where authentication is validated across multiple services
- You want truly stateless authentication where no server-side session storage is needed
- You have Cross-domain API access where cookies face CORS limitations
- You need to embed authorization data directly in the token

