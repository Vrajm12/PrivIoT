/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/v2/:path*',
        destination: 'http://127.0.0.1:8000/api/v2/:path*',
      },
      {
        source: '/health/:path*',
        destination: 'http://127.0.0.1:8000/health/:path*',
      },
    ];
  },
};

export default nextConfig;
