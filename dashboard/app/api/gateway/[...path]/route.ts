import { NextRequest } from "next/server";

import { proxyJsonRequest } from "../../../../lib/proxy-server";

const GATEWAY_CAPABILITIES: Record<string, string> = {
  "mcp/tools/list": "mcp:read",
  "mcp/tools/call": "mcp:invoke",
  "mcp/resources/list": "mcp:read",
  "mcp/resources/read": "mcp:read",
  "mcp/prompts/list": "mcp:read",
  "mcp/prompts/get": "mcp:read",
};

export async function GET(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleProxy(request, path, "GET");
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleProxy(request, path, "POST", await request.text());
}

async function handleProxy(request: NextRequest, path: string[], method: string, body?: string) {
  const backendBase = process.env.AGENTOPS_SERVER_API_URL ?? process.env.NEXT_PUBLIC_AGENTOPS_API_URL ?? "http://localhost:8000";
  const gatewayBase = process.env.AGENTOPS_SERVER_GATEWAY_URL ?? process.env.NEXT_PUBLIC_AGENTOPS_GATEWAY_URL ?? "http://localhost:8001";
  const authResponse = await fetch(`${backendBase}/v1/auth/context`, {
    headers: request.headers.get("cookie") ? { cookie: request.headers.get("cookie") as string } : {},
    cache: "no-store",
  });

  if (authResponse.status === 401) {
    return new Response(JSON.stringify({ detail: "Authentication required" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (!authResponse.ok) {
    return new Response(await authResponse.text(), {
      status: authResponse.status,
      headers: { "Content-Type": authResponse.headers.get("Content-Type") ?? "application/json" },
    });
  }

  const auth = (await authResponse.json()) as { capabilities?: string[]; is_operator?: boolean };
  const required = GATEWAY_CAPABILITIES[path.join("/")];
  const capabilities = auth.capabilities ?? [];
  const allowed = Boolean(required) && (
    auth.is_operator
    || capabilities.includes(required)
    || capabilities.includes(`${required.split(":", 1)[0]}:*`)
    || capabilities.includes("admin:*")
  );
  if (!allowed) {
    return new Response(JSON.stringify({ detail: "Capability denied" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  return proxyJsonRequest({
    base: gatewayBase,
    path,
    request,
    method,
    body,
  });
}
