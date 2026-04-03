import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: { tenantId: string } }) {
    const backendUrl = process.env.BACKEND_API_URL || "http://localhost:8000";
    const apiKey = process.env.BACKEND_API_KEY;

    if (!apiKey) {
        console.error("[SSE Proxy] ERROR: BACKEND_API_KEY is not set.");
        return new Response("Server Configuration Error", { status: 500 });
    }

    const targetUrl = `${backendUrl}/api/v1/events/stream`;

    try {
        const response = await fetch(targetUrl, {
            headers: {
                "Authorization": `Bearer ${apiKey}`,
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
