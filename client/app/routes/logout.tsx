import { redirect } from "@remix-run/react";
import { destroySession, getSession } from "~/utils/session.server";

export async function loader({ request }: { request: Request }) {
    const session = await getSession(request);
    const tokens = session.get("tokens");

    const res = await fetch("http://localhost:5168/auth/logout", {
        headers: {
            "Authorization": `Bearer ${tokens.access_token}`,
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
}

export function Logout() {
    return
}