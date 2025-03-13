import { LoaderFunctionArgs } from "@remix-run/node";
import { Form, json, redirect, useActionData } from "@remix-run/react";
import { getSession } from "~/utils/session.server";

export async function action({ request }: { request: Request }) {
    return redirect("https://localhost:7084/auth/login?provider=Google&returnUrl=http://localhost:5173/auth-cb");
}

export async function loader({ request }: LoaderFunctionArgs) {
    const session = await getSession(request);

    if (session.get("authenticated")) {
        return redirect("/account");
    }

    return null;
}


export default function Login() {

    return (
        <div className="grid place-items-center w-full">
            <Form method="post" className="mt-40">
                <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Login With Google</button>
            </Form>
        </div>
    );
}
