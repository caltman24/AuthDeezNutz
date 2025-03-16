import { ActionFunctionArgs, LoaderFunctionArgs } from "@remix-run/node";
import { Form, json, redirect, useLoaderData } from "@remix-run/react";
import { useAuth } from "~/context/auth";
import { destroySession, getSession } from "~/utils/session.server";

export async function loader({ request }: LoaderFunctionArgs) {
    const session = await getSession(request);

    if (!session.get("authenticated")) {
        return redirect("/login");
    }


    return Response.json({
        claims: session.get("claims"),
    });
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