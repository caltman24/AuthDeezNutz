import { redirect } from "@remix-run/react";
import { destroySession, getSession } from "~/utils/session.server";

export async function loader({ request }: { request: Request }) {
    const session = await getSession(request);

    const res = await fetch("http://localhost:5168/auth/logout", {
        headers: {
            "Cookie": request.headers.get("Cookie") || ""
        }
    });

    const authCookie = res.headers.get("set-cookie");

    session.unset("authenticated");

    return redirect("/", {
        headers: {
            "Set-Cookie": [await destroySession(session), authCookie].filter(Boolean).join(", ")
        },
    });
}

export function Logout() {
    return
}