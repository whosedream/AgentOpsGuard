import { NextRequest } from "next/server";

import { proxyJsonRequest, ANONYMOUS_BACKEND_PATHS } from "../../../../lib/proxy-server";

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
  const normalizedPath = path.join("/");
  return proxyJsonRequest({
    base,
    path,
    request,
    method,
    body,
    allowAnonymous: ANONYMOUS_BACKEND_PATHS.has(normalizedPath),
  });
}
