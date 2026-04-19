import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Routes that don't require authentication
const publicRoutes = ['/login', '/signup', '/forgot-password', '/api/v1/auth/login'];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // 1. Check if the route is public
  const isPublicRoute = publicRoutes.some((route) => pathname.startsWith(route));

  // 2. Extract token from cookies (Standard Next.js practice)
  // Note: Currently the frontend uses localStorage, which is NOT accessible in middleware.
  // We should ideally move to httpOnly cookies for better security.
  // For now, we'll check for a cookie named 'sentinel_token'.
  const token = request.cookies.get('sentinel_token')?.value;

  // 3. If no token and not a public route, redirect to login
  if (!token && !isPublicRoute && !pathname.startsWith('/_next') && !pathname.includes('.')) {
    const url = request.nextUrl.clone();
    url.pathname = '/login';
    // Store the original destination to redirect back after login
    url.searchParams.set('from', pathname);
    return NextResponse.redirect(url);
  }

  // 4. If token exists and user is on login page, redirect to dashboard
  if (token && pathname === '/login') {
    const url = request.nextUrl.clone();
    url.pathname = '/';
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

// See "Matching Paths" below to learn more
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
