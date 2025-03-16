import { redirect } from "@remix-run/react";
import { destroySession, getSession } from "~/utils/session.server";

export async function loader({ request }: { request: Request }) {
    const session = await getSession(request);
    return redirect("/", {
        headers: {
            "Set-Cookie": await destroySession(session),
        },
    });
}

export function Logout() {
    return
}