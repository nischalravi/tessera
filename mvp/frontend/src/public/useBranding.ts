import { useEffect, useState } from "react";
import { PublicBranding, publicBranding } from "../api";

/** The tenant's branding for a public page (sign-in, claim, register, renew); null until it loads or when there is none. */
export function usePublicBranding(slug: string): PublicBranding | null {
  const [b, setB] = useState<PublicBranding | null>(null);
  useEffect(() => {
    let live = true;
    setB(null);
    if (slug) publicBranding(slug).then((r) => live && setB(r));
    return () => { live = false; };
  }, [slug]);
  return b;
}
