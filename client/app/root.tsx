import {
  Link,
  Links,
  Meta,
  Outlet,
  Scripts,
  ScrollRestoration,
  useLoaderData,
} from "@remix-run/react";
import type { LinksFunction, LoaderFunctionArgs } from "@remix-run/node";

import "./tailwind.css";
import { getSession } from "./utils/session.server";
import { AuthContextType, AuthProvider, UserClaim } from "./context/auth";

export const links: LinksFunction = () => [
  { rel: "preconnect", href: "https://fonts.googleapis.com" },
  {
    rel: "preconnect",
    href: "https://fonts.gstatic.com",
    crossOrigin: "anonymous",
  },
  {
    rel: "stylesheet",
    href: "https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap",
  },
];


export async function loader({ request }: LoaderFunctionArgs) {
  const session = await getSession(request);
  console.log(session.get("tokens"))

  if (!session.get("authenticated")) {
    return Response.json({
      isAuthenticated: false,
    });
  }

  return Response.json({
    isAuthenticated: true,
  });
}

export function Layout({ children }: { children: React.ReactNode }) {
  const authData = useLoaderData<typeof loader>();

  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <Meta />
        <Links />
      </head>
      <body>
        <div className="bg-gray-300 py-3 shadow-sm mt-10">
          <nav className="max-w-7xl mx-auto flex justify-between items-center">
            <ul className="flex w-full gap-4">
              <li>
                <Link to="/" className="hover:underline">Home</Link>
              </li>
              {
                authData.isAuthenticated ? (
                  <>
                    <li>
                      <Link to="/account" prefetch="intent" className="hover:underline">Account</Link>
                    </li>
                    <li>

                      <Link to="/logout" className="hover:underline">Logout</Link>
                    </li>
                  </>
                ) : (
                  <li>
                    <Link to="/login" className="hover:underline">Login</Link>
                  </li>
                )
              }
            </ul>
          </nav>
        </div>
        {children}
        <ScrollRestoration />
        <Scripts />
      </body>
    </html >
  );
}

export default function App() {
  return <Outlet />;
}
