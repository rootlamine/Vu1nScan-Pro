/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cream:        '#FFFBF5',
        coral:        '#FF6B6B',
        'coral-light':'#FFF0F0',
        violet:       '#7C6FF7',
        'violet-light':'#F0EEFF',
        navy:         '#1C1C2E',
        mid:          '#6B6B8A',
        success:      '#4ECDC4',
        'success-light':'#E8FFFE',
        warning:      '#FFB347',
        'warning-light':'#FFF7E6',
        border:       '#EDE8FF',
      },
      fontFamily: {
        sans: ['Sora', 'sans-serif'],
        mono: ['Space Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};
