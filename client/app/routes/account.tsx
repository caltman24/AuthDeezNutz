import { ActionFunctionArgs, LoaderFunctionArgs } from "@remix-run/node";
import { Form, json, redirect, useLoaderData } from "@remix-run/react";
import { useAuth } from "~/context/auth";
import { getSession } from "~/utils/session.server";
import { BearerToken } from "./auth-cb";

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