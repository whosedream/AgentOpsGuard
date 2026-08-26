import { NextRequest } from "next/server";

import { buildProxyTarget } from "./proxy";

type ProxyOptions = {
  base: string;
  path: string[];
  request: NextRequest;
  method: string;
  body?: string;
  allowAnonymous?: boolean;
  authHeaders?: Record<string, string>;
};

export const ANONYMOUS_BACKEND_PATHS = new Set(["v1/health", "healthz", "readyz"]);

function copyHeaders(source: Headers, target: Headers, keys: string[]) {
  for (const key of keys) {
    const value = source.get(key);
    if (value) target.set(key, value);
  }
}

export async function proxyJsonRequest({
  base,
  path,
  request,
  method,
  body,
  allowAnonymous = false,
  authHeaders,
}: ProxyOptions): Promise<Response> {
  const normalizedPath = path.join("/");
  const target = buildProxyTarget(base, path, request.nextUrl.search);
  const outgoingHeaders = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) {
    outgoingHeaders.set("content-type", contentType);
  } else if (body !== undefined) {
    outgoingHeaders.set("content-type", "application/json");
  }

  if (!allowAnonymous) {
    const cookie = request.headers.get("cookie");
    if (cookie) outgoingHeaders.set("cookie", cookie);
  }

  if (authHeaders) {
    for (const [key, value] of Object.entries(authHeaders)) {
      outgoingHeaders.set(key, value);
    }
  }

  const upstream = await fetch(target, {
    method,
    body,
    headers: outgoingHeaders,
    cache: "no-store",
    redirect: "manual",
  });

  const responseHeaders = new Headers();
  copyHeaders(upstream.headers, responseHeaders, ["content-type"]);

  const setCookie = upstream.headers.get("set-cookie");
  if (setCookie) {
    responseHeaders.set("set-cookie", setCookie);
  }

  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: responseHeaders,
  });
}
