/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Low-saturation warm-neutral palette (no blue-purple gradients).
        sand: {
          50: '#faf8f5',
          100: '#f3efe8',
          200: '#e6ded1',
          300: '#d4c7b3',
          400: '#bda98d',
          500: '#a78e6f',
          600: '#8d7458',
          700: '#705c46',
          800: '#54463a',
          900: '#3a312b',
        },
        clay: {
          100: '#f6e8e2',
          500: '#b4664a',
          600: '#9a5138',
          700: '#7c402c',
        },
        moss: {
          100: '#e9ede2',
          500: '#6d7a53',
          600: '#57633f',
          700: '#444d32',
        },
      },
      fontFamily: {
        sans: ['ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
