import { redirect } from "@remix-run/react";
import { destroySession, getSession } from "~/utils/session.server";

export async function loader({ request }: { request: Request }) {
    const session = await getSession(request);

    const res = await fetch("http://localhost:5168/auth/logout", {
        credentials: "include",
        headers: {
            "Cookie": request.headers.get("Cookie") || "",
        }
    });
    console.log(res)

    if (res.status === 200) {
        return redirect("/", {
            headers: {
                "Set-Cookie": await destroySession(session),
            },
        });
    }

    return redirect("/");
}

export function Logout() {
    return
}