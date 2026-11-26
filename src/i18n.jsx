import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

const LangContext = createContext(null);
const KEY = 'htd-lang';

function initialLang() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === 'en' || saved === 'zh') return saved;
  } catch {
    /* storage unavailable */
  }
  return 'en';
}

export function LangProvider({ children }) {
  const [lang, setLang] = useState(initialLang);

  useEffect(() => {
    try {
      localStorage.setItem(KEY, lang);
    } catch {
      /* storage unavailable */
    }
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  }, [lang]);

  // tr() accepts a plain string or an { en, zh } object.
  const tr = useCallback(
    (value) => {
      if (value == null) return '';
      if (typeof value === 'string' || typeof value === 'number') return value;
      return value[lang] ?? value.en;
    },
    [lang],
  );

  const ctx = useMemo(() => ({ lang, setLang, tr }), [lang, tr]);
  return <LangContext.Provider value={ctx}>{children}</LangContext.Provider>;
}

export function useLang() {
  return useContext(LangContext);
}
