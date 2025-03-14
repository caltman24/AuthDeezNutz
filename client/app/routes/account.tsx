import { ActionFunctionArgs, LoaderFunctionArgs } from "@remix-run/node";
import { Form, json, redirect, useLoaderData } from "@remix-run/react";
import { useAuth } from "~/context/auth";
import { getSession } from "~/utils/session.server";

export async function loader({ request }: LoaderFunctionArgs) {
    const session = await getSession(request);

    if (!session.get("authenticated")) {
        return redirect("/login");
    }

    const res = await fetch("http://localhost:5168/", {
        credentials: "include",
        headers: {
            "Cookie": request.headers.get("Cookie") || ""
        }
    });

    if (!res.ok) {
        return Response.json([])
    }

    const data = await res.json();

    return Response.json(data)
}

export default function Account() {
    const data = useLoaderData<typeof loader>();

    return (
        <div>
            <h1>Account</h1>
            <pre>{JSON.stringify(data, null, 2)}</pre>]
        </div>
    );
}