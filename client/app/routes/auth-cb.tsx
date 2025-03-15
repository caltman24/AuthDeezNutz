import { LoaderFunctionArgs } from "@remix-run/node";
import { redirect } from "@remix-run/react";
import { commitSession, getSession } from "~/utils/session.server";

export async function loader({ request, params }: LoaderFunctionArgs) {

    const session = await getSession(request);

    const res = await fetch("http://localhost:5168/auth/user", {
        credentials: "include",
        headers: {
            "Cookie": request.headers.get("Cookie") || ""
        }
    });

    if (res.ok) {
        session.set("authenticated", true);
        session.set("claims", await res.json());

        return redirect("/", {
            headers: {
                "Set-Cookie": await commitSession(session),
            },
        });
    }

    return redirect("/login");
}

export function AuthCallback() {
    return (
        <div>
            <h1>Auth Callback</h1>
        </div>
    );
}