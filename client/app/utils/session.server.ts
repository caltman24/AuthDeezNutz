// app/utils/session.server.ts
import { createCookieSessionStorage } from "@remix-run/node";

const Hour = (n: number) => 60 * 60 * n;
const Day = (n: number) => Hour(24) * n;

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: "__session",
    secure: process.env.NODE_ENV === "production",
    secrets: [process.env.SESSION_SECRET || "s3cr3t"],
    sameSite: "lax",
    path: "/",
    maxAge: Hour(2), // 2 hours
    httpOnly: true,
  },
});

export async function getSession(request: Request) {
  return sessionStorage.getSession(request.headers.get("Cookie"));
}

export async function commitSession(session: any) {
  return sessionStorage.commitSession(session);
}

export async function destroySession(session: any) {
  return sessionStorage.destroySession(session);
}
