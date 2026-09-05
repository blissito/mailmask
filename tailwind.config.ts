/** @type {import('tailwindcss').Config} */
export default {
  content: ["./public/**/*.html", "./public/**/*.js"],
  theme: {
    extend: {
      colors: {
        mask: {
          50: "rgb(var(--mask-50) / <alpha-value>)",
          100: "rgb(var(--mask-100) / <alpha-value>)",
          400: "rgb(var(--mask-400) / <alpha-value>)",
          500: "rgb(var(--mask-500) / <alpha-value>)",
          600: "rgb(var(--mask-600) / <alpha-value>)",
          700: "rgb(var(--mask-700) / <alpha-value>)",
          800: "rgb(var(--mask-800) / <alpha-value>)",
          900: "rgb(var(--mask-900) / <alpha-value>)",
        },
        gold: { 400: "#facc15", 500: "#eab308" },
        // Tokens semánticos del sitio público (ver input.css). bg-bg, text-fg, border-line…
        bg: {
          DEFAULT: "rgb(var(--bg) / <alpha-value>)",
          elev: "rgb(var(--bg-elev) / <alpha-value>)",
          inset: "rgb(var(--bg-inset) / <alpha-value>)",
        },
        fg: {
          DEFAULT: "rgb(var(--fg) / <alpha-value>)",
          muted: "rgb(var(--fg-muted) / <alpha-value>)",
          subtle: "rgb(var(--fg-subtle) / <alpha-value>)",
        },
        line: "rgb(var(--line) / <alpha-value>)",
        accent: {
          DEFAULT: "rgb(var(--accent) / <alpha-value>)",
          text: "rgb(var(--accent-text) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "SF Mono", "Menlo", "monospace"],
      },
      keyframes: {
        fadeUp: {
          from: { opacity: "0", transform: "translateY(20px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        fadeLeft: {
          from: { opacity: "0", transform: "translateX(-8px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-10px)" },
        },
      },
      animation: {
        "fade-up": "fadeUp 0.5s ease-out forwards",
        "fade-left": "fadeLeft 0.4s ease-out forwards",
        "float": "float 3s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
