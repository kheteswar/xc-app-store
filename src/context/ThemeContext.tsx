import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export type Theme = 'dark' | 'warm' | 'light';   // warm = "Mid" (in-between)
export type Variant = 1 | 2 | 3;

// Modes shown in the selector, in brightness order.
export const THEME_MODES: { key: Theme; label: string }[] = [
  { key: 'dark', label: 'Dark' },
  { key: 'warm', label: 'Mid' },
  { key: 'light', label: 'Bright' },
];

// The 3 design variants offered for each mode.
export const VARIANT_NAMES: Record<Theme, [string, string, string]> = {
  dark: ['Slate', 'Midnight', 'Carbon'],
  warm: ['Dusk', 'Sepia', 'Twilight'],
  light: ['Cool Gray', 'Airy White', 'Warm Paper'],
};

interface ThemeValue {
  theme: Theme;
  variant: Variant;
  variants: Record<Theme, Variant>;
  setTheme: (m: Theme) => void;
  setVariant: (v: Variant) => void;
  applyTheme: (m: Theme, v: Variant) => void;
  cycleTheme: () => void;
}

const ThemeContext = createContext<ThemeValue>({
  theme: 'dark', variant: 1, variants: { dark: 1, warm: 1, light: 1 },
  setTheme: () => {}, setVariant: () => {}, applyTheme: () => {}, cycleTheme: () => {},
});

const DEFAULT_VARIANTS: Record<Theme, Variant> = { dark: 1, warm: 1, light: 1 };

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => (localStorage.getItem('xc-theme') as Theme) || 'dark');
  const [variants, setVariants] = useState<Record<Theme, Variant>>(() => {
    try { return { ...DEFAULT_VARIANTS, ...JSON.parse(localStorage.getItem('xc-theme-variants') || '{}') }; }
    catch { return { ...DEFAULT_VARIANTS }; }
  });

  const variant = variants[theme] || 1;

  useEffect(() => {
    const el = document.documentElement;
    el.setAttribute('data-theme', theme);
    el.setAttribute('data-variant', String(variant));
    localStorage.setItem('xc-theme', theme);
    localStorage.setItem('xc-theme-variants', JSON.stringify(variants));
  }, [theme, variant, variants]);

  const setTheme = (m: Theme) => setThemeState(m);
  const setVariant = (v: Variant) => setVariants(prev => ({ ...prev, [theme]: v }));
  const applyTheme = (m: Theme, v: Variant) => { setThemeState(m); setVariants(prev => ({ ...prev, [m]: v })); };
  const cycleTheme = () => setThemeState(t => (t === 'dark' ? 'warm' : t === 'warm' ? 'light' : 'dark'));

  return (
    <ThemeContext.Provider value={{ theme, variant, variants, setTheme, setVariant, applyTheme, cycleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
