import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0B0D0F",
        surface: {
          primary: "#111418",
          secondary: "#171B20",
          elevated: "#1D2228",
          border: "#292F36"
        },
        text: {
          primary: "#F2F4F5",
          secondary: "#A7AFB8",
          muted: "#6F7882"
        },
        accent: {
          DEFAULT: "#5EE6C1",
          hover: "#4CD4AF",
          glow: "rgba(94, 230, 193, 0.15)"
        },
        security: {
          critical: "#FF4D5F",
          high: "#FF8A3D",
          medium: "#F5C451",
          low: "#7FA7FF",
          verified: "#45D483",
          unknown: "#8B949E"
        }
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"]
      }
    },
  },
  plugins: [],
};
export default config;
