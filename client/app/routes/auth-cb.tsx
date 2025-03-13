import { LoaderFunctionArgs } from "@remix-run/node";
import { redirect } from "@remix-run/react";
import { commitSession, getSession } from "~/utils/session.server";

export async function loader({ request, params }: LoaderFunctionArgs) {
    const url = new URL(request.url);
    const access_token = url.searchParams.get("access_token");
    const refresh_token = url.searchParams.get("refresh_token");

    const session = await getSession(request);

    session.set("authenticated", true);
    session.set("tokens", { access_token, refresh_token });

    return redirect("/", {
        headers: {
            "Set-Cookie": await commitSession(session),
        },
    });
}

export function AuthCallback() {
    return (
        <div>
            <h1>Auth Callback</h1>
        </div>
    );
}