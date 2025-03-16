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