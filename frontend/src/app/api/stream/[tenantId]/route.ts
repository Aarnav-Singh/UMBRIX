import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: { tenantId: string } }) {
 const backendUrl = process.env.BACKEND_API_URL || "http://localhost:8000";

 const clientAuth = request.headers.get("Authorization");
 if (!clientAuth) {
 return new Response("Unauthorized", { status: 401 });
 }

 const targetUrl = `${backendUrl}/api/v1/events/stream`;

 try {
 const response = await fetch(targetUrl, {
 headers: {
 "Authorization": clientAuth,
 "Accept": "text/event-stream"
 }
 });

 return new Response(response.body, {
 headers: {
 "Content-Type": "text/event-stream",
 "Cache-Control": "no-cache",
 "Connection": "keep-alive"
 }
 });
 } catch (error) {
 console.error("[SSE Proxy] Error fetching SSE stream:", error);
 return new Response("Internal Server Error", { status: 500 });
 }
}
