# Bearer Token Authentication. Remix + .NET API
This branch demonstrates Bearer Token authentication between Remix and a .NET Api using Identity Framework and external identity providers like google.

This approach uses Opaque bearer tokens with refresh tokens to authorize requests. This works with remix because we can keep the tokens stored in the node server via cookieSessionStorage
so the tokens never make it to the browser. Going this route is simple and straight forward. The only downside is we need to implement token refresh and invalidations ourselves since the default Identity Api Endpoints kinda stink

## .NET API

### External Login Endpoint
Instead of passing the API's callback endpoint to the RedirectUri, pass the remix callback route. This passes the external identity cookie to the remix app.
The remix callback route, then attatches the cookie to a fetch request to the API's callback endpoint.

This flow is to prevent the tokens from being exposed to the browser.
```c#
// We pass in a redirect uri to a callback route on the remix app. The redirect after google auth provides the external cookie
authGroup.MapGet("/login-external", ([FromQuery] string provider, [FromQuery] string redirectUri) =>
  Results.Challenge(
    new AuthenticationProperties
    {
        RedirectUri = redirectUri,
        // We Need to pass the provider name to the callback endpoint for ExternalLoginSignInAsync to work
        Items = { { "LoginProvider", provider } }
    }, [provider]));
```

### Callback Endpoint
```c#
 // After the remix app gets a response from the login with the external cookie,
 // it will do a fetch request to this route with the external cookie
 // The external cookie is what contains the info from the external provider
        authGroup.MapGet("/callback", async (
            UserManager<AppUser> userManager,
            [FromServices] SignInManager<AppUser> signInManager) =>
        {
            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return Results.BadRequest("Failed to get info from Google");
            }

            // set the authentication scheme to bearer
            signInManager.AuthenticationScheme = IdentityConstants.BearerScheme;

            // try to sign in the user with this external login provider if the user already exists
            // this method calls SignInAsync internally and signs outs out of external scheme
            var result =
                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                return Results.Empty;
            }

            // user does not exist, create user
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
            {
                return Results.BadRequest("Failed to get info from Google. Missing email.");
            }

            // email is the canonical identifier for the user
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new AppUser
                {
                    Email = email,
                    UserName = email,
                    EmailConfirmed = true,
                    Role = "User"
                };

                await userManager.CreateAsync(user); // Add claims from external provider

                await userManager.AddClaimsAsync(user, [
                    new Claim("picture", info.Principal.FindFirstValue("picture") ?? ""),
                    new Claim(ClaimTypes.GivenName, info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? ""),
                    new Claim(ClaimTypes.Surname, info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "")
                ]);
            }

            //link the external login to the user
            await userManager.AddLoginAsync(user, info);
            await signInManager.SignInAsync(user, isPersistent: false);


            // SignInAsync handles returning the bearer tokens
            return Results.Empty;
        });
```

## Remix App

### Login Route
```Typescript
import { LoaderFunctionArgs, redirect } from "@remix-run/node";
import { commitSession, getSession } from "~/utils/session.server";

type LoginTokenResponse = {
    tokenType: string;
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}

export type BearerToken = Omit<LoginTokenResponse, "tokenType">;
export const createBearerToken = (token: LoginTokenResponse): BearerToken => {
    return {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        expiresIn: token.expiresIn,
    }
}

export async function loader({ request, params }: LoaderFunctionArgs) {
    const session = await getSession(request);

    const res = await fetch("http://localhost:5168/oauth/callback", {
        headers: {
            "Cookie": request.headers.get("Cookie") || "",
        }
    });

    if (res.ok) {
        session.set("authenticated", true);
        const tokenData = await res.json() as LoginTokenResponse;
        session.set("tokens", createBearerToken(tokenData));

        return redirect("/", {
            headers: {
                "Set-Cookie": await commitSession(session),
            },
        });
    }

    console.log("failed to login", res);

    return redirect("/login");

}

export function AuthCallback() {
    return null;
}
```

### Callback Route
```typescript
export async function loader({ request }: LoaderFunctionArgs) {
    const session = await getSession(request);
    const tokens = session.get("tokens") as BearerToken

    const res = await fetch("http://localhost:5168/", {
        headers: {
            "Authorization": `Bearer ${tokens.accessToken}`,
        }
    });

    // if (res.status === 401) {
    //     const res = await fetch("http://localhost:5168/auth/refresh", {
    //         headers: {
    //             "Authorization": `Bearer ${tokens.accessToken}`,
    //         }
    //     });
    // }

    return Response.json(await res.json());

}

export default function Account() {
    const authData = useLoaderData<typeof loader>();

    return (
        <div>
            <h1>Account</h1>
            <pre>{JSON.stringify(authData, null, 2)}</pre>
        </div>
    );
}
```
