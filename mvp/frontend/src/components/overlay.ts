import { type RefObject, useEffect, useRef } from "react";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Where focus should go inside a modal: the marked autofocus element, else the first focusable, else the modal itself. */
export function focusTarget<T>(autofocus: T | null, focusables: T[], container: T): T {
  return autofocus ?? focusables[0] ?? container;
}

const target = (m: HTMLElement) => focusTarget(m.querySelector<HTMLElement>("[data-autofocus]"), Array.from(m.querySelectorAll<HTMLElement>(FOCUSABLE)), m);

/**
 * Modal behaviour for drawers, dialogs and the command palette:
 * Escape closes, Tab is trapped inside, focus moves in on open and is restored on close.
 */
/** Open modals, innermost last: only the top one reacts to Escape / Tab. */
const stack: symbol[] = [];

export function useModal(ref: RefObject<HTMLElement | null>, onClose: () => void, opts: { initialFocus?: boolean } = {}) {
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const me = Symbol("modal");
    stack.push(me);
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    if (el && opts.initialFocus !== false) {
      if (!el.hasAttribute("tabindex")) el.tabIndex = -1;
      target(el).focus();
    }
    // When the focused control is swapped out (a dialog moving to its success state), the browser drops focus to
    // <body>; move it to the new content's target so Enter works and the Tab trap holds until close.
    const refocus = () => {
      const m = ref.current;
      if (!m || stack[stack.length - 1] !== me || m.contains(document.activeElement)) return;
      if (document.activeElement && document.activeElement !== document.body) return; // focus deliberately went elsewhere
      target(m).focus();
    };
    const mo = el ? new MutationObserver(refocus) : null;
    if (el) mo?.observe(el, { childList: true, subtree: true });
    const onKey = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== me) return;
      // an open dropdown inside the modal handles its own Escape first
      if (e.key === "Escape" && (e.target as Element | null)?.closest?.('[role="menu"]')) return;
      if (e.key === "Escape") {
        e.stopPropagation();
        close.current();
        return;
      }
      if (e.key === "Tab" && ref.current) {
        if (!ref.current.contains(document.activeElement)) {
          e.preventDefault();
          target(ref.current).focus();
          return;
        }
        const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null);
        if (!items.length) return;
        const first = items[0], last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      mo?.disconnect();
      document.removeEventListener("keydown", onKey, true);
      stack.splice(stack.indexOf(me), 1);
      prev?.focus?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

/** True when focus is in a text field, where single-key shortcuts must not fire. */
export function isTyping(e: KeyboardEvent) {
  const t = e.target as HTMLElement | null;
  if (!t) return false;
  const tag = t.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || t.isContentEditable;
}

/** True while any drawer, dialog or the palette is open; page-level shortcuts should pause. */
export const modalOpen = () => stack.length > 0;
