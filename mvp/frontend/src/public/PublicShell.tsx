import { ReactNode, useEffect, useRef } from "react";
import { PublicBranding } from "../api";
import { brandStyle } from "../branding";
import { BrandMark } from "./BrandMark";
import { Callout } from "../components/Feedback";
import { MessageKey, setLocale, t } from "../i18n";

/**
 * What the public pages (claim, register, renew) share: the page language from the browser, the
 * document title, the brand line and the one `main` landmark, labelled by the page's heading. No
 * navigation, no third-party scripts. The pages are English-only today; the language attribute and
 * the catalog (src/i18n) are in place so a translation is a new file, not a rewrite.
 */
export function PublicShell({ titleKey, brand, branding, children }: { titleKey: MessageKey; brand?: string; branding?: PublicBranding | null; children: ReactNode }) {
  const name = branding?.configured ? branding.name : brand ?? t("brand.default");
  const lang = setLocale(typeof navigator === "undefined" ? [] : navigator.languages ?? [navigator.language]);
  useEffect(() => {
    document.documentElement.lang = lang;
    document.title = `${t(titleKey)} · ${name}`;
  }, [lang, titleKey, name]);
  return (
    <div className="claim-wrap" style={brandStyle(branding)}>
      <main className="claim" aria-labelledby="claim-title">
        <p className="claim-brand"><BrandMark branding={branding} name={name} /></p>
        {children}
      </main>
    </div>
  );
}

/** The page or step heading. It takes focus when it appears, so a screen reader starts at the new step. */
export function PublicHeading({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => ref.current?.focus(), []);
  return <h1 id="claim-title" tabIndex={-1} ref={ref} className="claim-h">{children}</h1>;
}

/**
 * Where errors are announced. The container is always in the page and has role="alert", so a message put
 * into it is read out at once; the callout inside is what is seen.
 */
export function ErrorAlert({ message, id }: { message: string | null | undefined; id?: string }) {
  return <div role="alert" id={id}>{message ? <Callout tone="bad">{message}</Callout> : null}</div>;
}

/** Where progress and confirmations are announced politely. */
export function StatusRegion({ children }: { children?: ReactNode }) {
  return <div role="status" aria-live="polite">{children}</div>;
}
