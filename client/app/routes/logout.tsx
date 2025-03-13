import { redirect } from "@remix-run/react";
import { destroySession, getSession } from "~/utils/session.server";

export async function loader({ request }: { request: Request }) {
    const res = await fetch("http://localhost:5168/auth/logout", {
        credentials: "include",
        headers: {
            "Accept": "application/json",
            "cookie": request.headers.get("Cookie") || ""
        }
    });

    if (res.status === 200) {
        const session = await getSession(request);

        return redirect("/", {
            headers: {
                "Set-Cookie": await destroySession(session),
            },
        });
    }
}

export function Logout() {
    return
}