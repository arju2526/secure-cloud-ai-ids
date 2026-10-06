/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'soc-bg': '#0f172a',
        'soc-card': '#1e293b',
        'soc-border': '#334155',
      }
    },
  },
  plugins: [],
}
