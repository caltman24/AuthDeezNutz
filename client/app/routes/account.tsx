import { ActionFunctionArgs, LoaderFunctionArgs } from "@remix-run/node";
import { Form, json, redirect, useLoaderData } from "@remix-run/react";
import { useAuth } from "~/context/auth";
import { getSession } from "~/utils/session.server";

export default function Account() {
    return (
        <div>
            <h1>Account</h1>
        </div>
    );
}