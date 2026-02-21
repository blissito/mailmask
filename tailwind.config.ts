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
