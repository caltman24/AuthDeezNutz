# Bearer Token Authentication. Remix + .NET API
This branch demonstrates Bearer Token authentication between Remix and a .NET Api using Identity Framework and external identity providers like google.

This approach uses Opaque bearer tokens with refresh tokens to authorize requests. This works with remix because we can keep the tokens stored in the node server via cookieSessionStorage
so the tokens never make it to the browser. Going this route is simple and straight forward. The only downside is we need to implement token refresh and invalidations ourselves since the default Identity Api Endpoints kinda stink
