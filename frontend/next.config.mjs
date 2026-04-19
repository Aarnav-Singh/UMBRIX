import { withSentryConfig } from "@sentry/nextjs";

/** @type {import('next').NextConfig} */
const nextConfig = {
    output: "standalone",
    eslint: { ignoreDuringBuilds: true },
    typescript: { ignoreBuildErrors: true },
    async headers() {
        return [
            {
                source: "/(.*)",
                headers: [
                    { key: "X-DNS-Prefetch-Control", value: "on" },
                    { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
                    { key: "X-XSS-Protection", value: "1; mode=block" },
                    { key: "X-Frame-Options", value: "SAMEORIGIN" },
                    { key: "X-Content-Type-Options", value: "nosniff" },
                    { key: "Referrer-Policy", value: "origin-when-cross-origin" },
                    { 
                        key: "Content-Security-Policy", 
                        value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none';" 
                    }
                ],
            },
        ];
    },
    experimental: {
        instrumentationHook: true,
    },
};

export default withSentryConfig(nextConfig, {
    // Suppress source map upload logs during builds
    silent: true,

    // Upload source maps for better error stack traces
    widenClientFileUpload: true,

    // Route browser requests to Sentry through a Next.js rewrite to avoid ad-blockers
    tunnelRoute: "/monitoring",

    // Automatically tree-shake Sentry logger statements to reduce bundle size  
    disableLogger: true,

    // Hide source maps from browser devtools in production
    hideSourceMaps: true,
});
