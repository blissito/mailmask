/** @type {import('tailwindcss').Config} */
export default {
  content: ["./public/**/*.html"],
  theme: {
    extend: {
      colors: {
        mask: {
          50: "#fef2f2",
          100: "#fee2e2",
          400: "#f87171",
          500: "#ef4444",
          600: "#dc2626",
          700: "#b91c1c",
          800: "#991b1b",
          900: "#7f1d1d",
        },
        gold: { 400: "#facc15", 500: "#eab308" },
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
      },
      animation: {
        "fade-up": "fadeUp 0.5s ease-out forwards",
        "fade-left": "fadeLeft 0.4s ease-out forwards",
      },
    },
  },
  plugins: [],
};
