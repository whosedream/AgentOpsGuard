import { NextRequest } from "next/server";
import { buildProxyTarget } from "../../../../lib/proxy";

export async function GET(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleProxy(request, path, "GET");
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleProxy(request, path, "POST", await request.text());
}

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleProxy(request, path, "PATCH", await request.text());
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return handleProxy(request, path, "DELETE");
}

async function handleProxy(request: NextRequest, path: string[], method: string, body?: string) {
  const base = process.env.AGENTOPS_SERVER_API_URL ?? process.env.NEXT_PUBLIC_AGENTOPS_API_URL ?? "http://localhost:8000";
  const target = buildProxyTarget(base, path, request.nextUrl.search);
  const response = await fetch(target, {
    method,
    body,
    headers: {
      "Content-Type": "application/json",
      "X-AgentOps-Api-Key": process.env.AGENTOPS_SERVER_API_KEY ?? process.env.AGENTOPS_API_KEY ?? "dev-agentops-key",
    },
    cache: "no-store",
  });
  return new Response(await response.text(), {
    status: response.status,
    headers: { "Content-Type": response.headers.get("Content-Type") ?? "application/json" },
  });
}
