import { headers } from "next/headers";

import type { AuthContext } from "./api";

type ServerFetchOptions = RequestInit & {
  allowUnauthorized?: boolean;
};

function normalizeBaseUrl(origin: string): string {
  return origin.endsWith("/") ? origin.slice(0, -1) : origin;
}

async function request<T>(path: string, init: ServerFetchOptions = {}): Promise<T> {
  const incomingHeaders = await headers();
  const host = incomingHeaders.get("x-forwarded-host") ?? incomingHeaders.get("host");
  const protocol = incomingHeaders.get("x-forwarded-proto") ?? "http";
  if (!host) {
    throw new Error("Dashboard host header is missing");
  }

  const baseUrl = normalizeBaseUrl(`${protocol}://${host}`);
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      ...(incomingHeaders.get("cookie") ? { cookie: incomingHeaders.get("cookie") as string } : {}),
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });

  if (response.status === 401 && init.allowUnauthorized) {
    throw Object.assign(new Error("Unauthorized"), { status: 401 });
  }

  if (!response.ok) {
    const detail = await response.text();
    throw Object.assign(new Error(detail || `${path} failed`), { status: response.status });
  }

  return response.json() as Promise<T>;
}

export async function serverApiGet<T>(path: string, init: ServerFetchOptions = {}): Promise<T> {
  return request<T>(`/api/backend${path}`, { ...init, method: init.method ?? "GET" });
}

export async function serverAuthContext(): Promise<AuthContext> {
  return serverApiGet<AuthContext>("/v1/auth/context", { allowUnauthorized: true });
}
