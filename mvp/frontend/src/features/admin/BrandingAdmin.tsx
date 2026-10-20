import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from "react";
import { BrandingSettings, brandingApi, relTime, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Button, Callout, Loading, useToast } from "../../components";
import { MIN_CONTRAST, bestOn, brandStyle, contrast, isHex, pairProblem } from "../../branding";
import { BrandMark } from "../../public/BrandMark";
import { errText } from "./common";

/**
 * Branding: the product name, button colours and logo the sign-in page, the guest claim pages and emails show.
 * The API enforces the same rules as the form: the colour pair must reach WCAG AA, the logo is a PNG or JPEG
 * (never SVG) within the size and dimension limits. Emails are plain text, so they carry the name only.
 */

const toBase64 = (buf: ArrayBuffer) => {
  let s = "";
  const b = new Uint8Array(buf);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
};

export function BrandingAdmin() {
  const { data, error, reload } = useApi<BrandingSettings>("/admin/branding");
  const { can, session } = useSession();
  const edit = can("email.manage");
  const toast = useToast();
  const [name, setName] = useState("");
  const [primary, setPrimary] = useState("#0f6cbd");
  const [on, setOn] = useState(""); // "" = automatic
  const [file, setFile] = useState<{ type: string; data: string; url: string; bytes: number } | null>(null);
  const [removeLogo, setRemoveLogo] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!data) return;
    setName(data.display_name);
    setPrimary(data.primary_color);
    setOn(data.configured && data.on_primary_color !== bestOn(data.primary_color) ? data.on_primary_color : "");
  }, [data]);
  useEffect(() => () => { if (file) URL.revokeObjectURL(file.url); }, [file]);

  const effectiveOn = on || (isHex(primary) ? bestOn(primary) : "#ffffff");
  const pair = useMemo(() => pairProblem(primary, on), [primary, on]);
  const ratio = isHex(primary) && isHex(effectiveOn) ? contrast(primary, effectiveOn) : null;
  const preview = { configured: true, primary_color: primary, on_primary_color: effectiveOn };
  const savedLogo = data?.logo && !removeLogo ? `/api/auth/branding/logo?tenant=${encodeURIComponent(session.tenant.slug)}&v=${data.logo.sha256.slice(0, 12)}` : null;
  const logoUrl = file ? file.url : savedLogo;

  if (!data) return <div className="card flush"><Loading error={error} /></div>;
  const lim = data.limits;

  const pick = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    setProblem(null);
    if (!f) return;
    if (!lim.logo_types.includes(f.type)) return setProblem("The logo must be a PNG or JPEG image. SVG is not accepted.");
    if (f.size > lim.logo_max_bytes) return setProblem(`The logo is ${Math.ceil(f.size / 1024)} KiB; the limit is ${lim.logo_max_bytes >> 10} KiB.`);
    const url = URL.createObjectURL(f);
    const dims = await new Promise<{ w: number; h: number } | null>((res) => {
      const im = new Image();
      im.onload = () => res({ w: im.naturalWidth, h: im.naturalHeight });
      im.onerror = () => res(null);
      im.src = url;
    });
    if (!dims) { URL.revokeObjectURL(url); return setProblem("That file cannot be read as an image."); }
    if (dims.w < lim.logo_min_px || dims.h < lim.logo_min_px || dims.w > lim.logo_max_px || dims.h > lim.logo_max_px) {
      URL.revokeObjectURL(url);
      return setProblem(`The logo is ${dims.w}×${dims.h} pixels; it must be between ${lim.logo_min_px}×${lim.logo_min_px} and ${lim.logo_max_px}×${lim.logo_max_px}.`);
    }
    setFile({ type: f.type, data: toBase64(await f.arrayBuffer()), url, bytes: f.size });
    setRemoveLogo(false);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setProblem(null);
    if (pair) return setProblem(pair);
    setBusy(true);
    try {
      await brandingApi.save({
        display_name: name.trim(), primary_color: primary.toLowerCase(), on_primary_color: on || undefined,
        logo: file ? { content_type: file.type, data_base64: file.data } : undefined, remove_logo: removeLogo || undefined,
      });
      setFile(null);
      setRemoveLogo(false);
      toast("Branding saved");
      reload();
    } catch (err) {
      setProblem(errText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card stack" style={{ maxWidth: 720 }}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Product name
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required disabled={!edit} aria-describedby="brand-name-help" />
          <span id="brand-name-help" className="xs faint">Shown where “Tessera” would be: the sign-in and claim pages, and the subject and footer of emails.</span>
        </label>
        <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap" }}>
          <label className="field">Button colour
            <span className="row tight">
              <input type="color" aria-label="Button colour picker" value={isHex(primary) ? primary : "#000000"} onChange={(e) => setPrimary(e.target.value)} disabled={!edit} />
              <input className="input sys" style={{ width: 110 }} value={primary} onChange={(e) => setPrimary(e.target.value)} maxLength={7} spellCheck={false} disabled={!edit} />
            </span>
          </label>
          <label className="field">Button text
            <select className="input" value={on ? "custom" : "auto"} onChange={(e) => setOn(e.target.value === "auto" ? "" : effectiveOn)} disabled={!edit}>
              <option value="auto">Automatic (white or black)</option>
              <option value="custom">Choose a colour</option>
            </select>
          </label>
          {on !== "" && (
            <label className="field">Text colour
              <input className="input sys" style={{ width: 110 }} value={on} onChange={(e) => setOn(e.target.value)} maxLength={7} spellCheck={false} disabled={!edit} />
            </label>
          )}
        </div>
        <div aria-live="polite" className="small">
          {ratio !== null && (
            <span className={pair ? "" : "muted"}>
              Contrast {ratio.toFixed(2)}:1 {pair ? `is below the ${MIN_CONTRAST}:1 AA minimum. ${pair}` : "(meets WCAG AA)."}
            </span>
          )}
        </div>
        <div className="stack-sm">
          <span className="small strong">Logo</span>
          <div className="row">
            {edit && <label className="btn" style={{ cursor: "pointer" }}>
              Choose a logo
              <input type="file" accept="image/png,image/jpeg" onChange={pick} className="sr-only" aria-describedby="brand-logo-help" />
            </label>}
            {edit && (data.logo || file) && !removeLogo && <Button onClick={() => { setRemoveLogo(true); setFile(null); }}>Remove logo</Button>}
          </div>
          <span id="brand-logo-help" className="xs faint">PNG or JPEG (not SVG), at most {lim.logo_max_bytes >> 10} KiB, {lim.logo_min_px} to {lim.logo_max_px} pixels each way.</span>
          {data.logo && !file && !removeLogo && <span className="xs faint">Current logo: {data.logo.width}×{data.logo.height} {data.logo.content_type === "image/png" ? "PNG" : "JPEG"}.</span>}
          {file && <span className="xs faint">New logo selected ({Math.ceil(file.bytes / 1024)} KiB). It is saved with the form.</span>}
          {removeLogo && <span className="xs faint">The logo is removed when you save.</span>}
        </div>
        <div aria-live="polite">{problem && <Callout tone="bad">{problem}</Callout>}</div>
        <div className="stack-sm">
          <span className="small strong">Preview</span>
          <div className="brand-preview" style={brandStyle(pair ? null : preview)}>
            <BrandMark name={name || "Tessera"} branding={logoUrl ? { name, configured: true, primary_color: primary, on_primary_color: effectiveOn, logo_url: logoUrl } : null} />
            <span className="small muted">Sign in to {name || "Tessera"}</span>
            <span><button type="button" className="btn primary" tabIndex={-1}>Continue</button></span>
          </div>
        </div>
        {edit ? (
          <div className="row"><Button type="submit" variant="primary" disabled={busy || !!pair || !name.trim()}>{busy ? "Saving…" : "Save branding"}</Button></div>
        ) : (
          <p className="small muted">Changing branding needs the email.manage permission (tenant admin).</p>
        )}
        {data.updated_by && <p className="xs faint">Last changed by {data.updated_by} {data.updated_at && relTime(data.updated_at)}. Saving needs a recent strong sign-in; if it asks for one, sign in and save again.</p>}
      </form>
    </div>
  );
}
