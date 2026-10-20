# WCAG 2.2 AA audit

Issue #173 · checklist row "Accessible interface" (#157) · audited 2026-10-12 on
`agent/173-a11y` (the Phase 0 auth branch plus this PR) · scope: the web UI in `mvp/frontend`,
signed out (sign-in) and signed in, light and dark themes.

## Result

**No open AA blockers.** The audit found 9 issues; all are fixed in this PR (table below). CI
now guards the criteria that can be tested by machine: `npm run test:a11y`, workflow
`.github/workflows/a11y.yml`.

One part is still open: **a screen-reader pass with NVDA and VoiceOver**. Automated rules
and code review cannot prove that announcements make sense in context. A human must do it
before the checklist row is closed. See "Still to do by hand".

## Method

1. **Automated rules, every route.** axe-core 4.11 (via `@axe-core/playwright` 4.13.0) runs
   the WCAG 2.0, 2.1 and 2.2 A/AA rule sets. It runs on the sign-in page, on all 29 routes of
   `src/app/App.tsx` (redirect-only routes excluded), on an identity and a connection detail
   page, and on 5 main pages in the dark theme. Any serious or critical violation fails the
   run (`e2e/a11y.spec.ts`). A one-off scan that also included moderate, minor and
   best-practice rules found two more issues, both fixed.
2. **Scripted checks axe does not make** (`e2e/wcag22.spec.ts`):
   - reflow at 320 CSS px on 7 main routes (1.4.10);
   - the WCAG text-spacing overrides (1.4.12);
   - Tab and Shift+Tab through long pages at a 600 px viewport, checking that the sticky top
     bar never covers the focused element (2.4.11).
3. **Keyboard-only walkthrough** (`e2e/keyboard.spec.ts`), using only the keyboard after each
   page load:
   - sign in;
   - request access;
   - approve an approval;
   - keep a privileged review item (its reason dialog included);
   - the skip link;
   - the command palette's focus trap and Escape.

   Every stop is checked for a visible focus indicator (2.1.1, 2.1.2, 2.4.1, 2.4.3, 2.4.7).
4. **Criterion-by-criterion review** of the components (`src/components`), styles and the
   pages above, for what tools cannot judge: text alternatives, labels, error messages,
   timing, consistency and authentication.

## Findings (all fixed)

| # | Criterion | Where | Problem | Fix |
|---|---|---|---|---|
| 1 | 4.1.2 Name, Role, Value | Risk, review progress, readiness score and reconciliation bars | `role="meter"` without an accessible name | `Bar` takes a `label`, and defaults to "N of M" / "Risk N of M" |
| 2 | 4.1.2 (nested-interactive) | Inbox list | `role="option"` rows contained a checkbox and buttons | A `role="list"` of rows with `aria-current`. Keyboard selection stays on j/k and the arrow keys; the row actions are reached with Tab |
| 3 | 4.1.2 (nested-interactive), 2.5.8 Target Size | Lifecycle → HRIS feed | Option rows contained identity links (small targets) | Each row is one `<button aria-pressed>` with the identity's name. The identity link is in the plan panel |
| 4 | 4.1.2 (aria-conditional-attr) | Identity → Permissions table | `aria-expanded` on a table row (not allowed for `row`) | A disclosure `<button aria-expanded>` in the first cell |
| 5 | 1.4.3 Contrast (Minimum) | Filter-chip counts (inbox, request, connection pages) | Count at 80 % opacity fell below 4.5:1 | Full opacity |
| 6 | 1.4.1 Use of Color | Links inside sentences (home "at a glance", review summary) | Links told apart by colour only | Links inside running text are underlined |
| 7 | 1.4.10 Reflow | Request access | An inline grid column (380 px) overrode the narrow layout, so the page scrolled sideways at 320 px | The side width is a CSS variable, and the narrow breakpoint stacks the columns again |
| 8 | 2.4.11 Focus Not Obscured | Every page | Nothing kept a focused element clear of the sticky 48 px top bar | `scroll-padding-top` on the root |
| 9 | 1.3.1 Info and Relationships (best practice) | Action columns (6 tables); graph side panel | Empty `<th>`; headings jumped from h1 to h3 | A visually hidden "Actions" header; the graph sections are h2, styled as before |

## Criteria

**Status key:**
- **Pass** — met, with the evidence given.
- **N/A** — the UI has no such content.
- **Human** — needs the screen-reader pass.

### Perceivable

| Criterion | Status | Evidence |
|---|---|---|
| 1.1.1 Non-text Content | Pass | Icons are `aria-hidden`, and icon-only buttons carry `label` / `aria-label`. The access graph canvas is `role="img"` with a summary, and the same data is in the Selection panel and the identity pages. |
| 1.2.x Time-based media | N/A | No audio or video. |
| 1.3.1 Info and Relationships | Pass | Landmarks: `header`, `nav`, `main`. Real tables have header cells. Every form field has a `<label>` or `aria-label` (axe `label`, `select-name`). Headings are in order (finding 9). |
| 1.3.2 Meaningful Sequence | Pass | DOM order matches the visual order. Side panels follow their list. |
| 1.3.3 Sensory Characteristics | Pass | Instructions name controls by text ("Choose file…", "Retry"), never by shape or place alone. |
| 1.3.4 Orientation | Pass | No orientation lock. Works from 320 px up. |
| 1.3.5 Identify Input Purpose | Pass | The only field about the user on the sign-in page is their organisation (`autocomplete="organization"`). Identity is entered at the IdP. The admin forms collect no personal data about the user. |
| 1.4.1 Use of Color | Pass | Status badges carry text ("failed", "succeeded"), and risk colours are paired with numbers. Links in text are underlined (finding 6). |
| 1.4.3 Contrast (Minimum) | Pass | axe `color-contrast` passes on every route, light and dark (finding 5). |
| 1.4.4 Resize Text | Pass | Sizes are `rem`-based tokens. 200 % zoom equals the 640 px layout, which is covered by the reflow check. |
| 1.4.5 Images of Text | Pass | None. |
| 1.4.10 Reflow | Pass | 320 px check on 7 routes, with no sideways scrolling (finding 7). Data tables scroll inside their own region, which the exception allows. |
| 1.4.11 Non-text Contrast | Pass | Input borders `#8a8886` on white (3.5:1) and `#7a7a7a` on the dark surface (≥ 3:1). The focus ring `#0f6cbd` (5.4:1) / `#62abf5` on dark. Selected chips use a border plus a fill. |
| 1.4.12 Text Spacing | Pass | The overrides are applied on 7 routes; no clipping or sideways scroll. |
| 1.4.13 Content on Hover or Focus | Pass | Hover content is native `title` tooltips only. Menus and the command palette open on click or keystroke, and close with Escape. |

### Operable

| Criterion | Status | Evidence |
|---|---|---|
| 2.1.1 Keyboard | Pass | The keyboard walkthrough covers sign-in, request, approve and review. Clickable table rows also have a link or button in the row. The graph has zoom and fit buttons and is driven by the identity and resource pickers. |
| 2.1.2 No Keyboard Trap | Pass | Dialogs trap focus while open, and Escape returns focus (walkthrough). |
| 2.1.4 Character Key Shortcuts | Pass | Inbox j/k/a/d/r work only while the inbox has focus and not inside text fields, and the same actions are buttons. |
| 2.2.1 Timing Adjustable | Pass | No time limits on input. A session ends after inactivity, per the security policy (security exception), and the work in progress (the request draft) survives sign-in again. |
| 2.2.2 Pause, Stop, Hide | Pass | No auto-moving content. Toasts stay until dismissed or replaced. `prefers-reduced-motion` disables transitions. |
| 2.3.1 Three Flashes | Pass | No flashing content. |
| 2.4.1 Bypass Blocks | Pass | "Skip to content" is the first Tab stop and moves focus to `main` (walkthrough). |
| 2.4.2 Page Titled | Pass | Every page sets "Title · Tessera" (`Page`). |
| 2.4.3 Focus Order | Pass | The walkthrough follows DOM order through the rail, the command bar, the list and the panel. Opening a panel moves focus into it. |
| 2.4.4 Link Purpose (In Context) | Pass | Link text names its target ("Review in the inbox", "Open full page"). |
| 2.4.5 Multiple Ways | Pass | The left rail, the global search / command palette (Ctrl+K) and breadcrumbs. |
| 2.4.6 Headings and Labels | Pass | One h1 per page, h2 per card, descriptive labels. |
| 2.4.7 Focus Visible | Pass | Every walkthrough stop has an outline or a focus ring (checked in the test). |
| 2.4.11 Focus Not Obscured (Minimum) | Pass | Scripted Tab / Shift+Tab check (finding 8). Side panels are dialogs, so they never cover the focused element. |
| 2.5.1 Pointer Gestures | Pass | No path or multipoint gestures are required (graph pinch-zoom has buttons). |
| 2.5.2 Pointer Cancellation | Pass | Native buttons act on click (pointer up). |
| 2.5.3 Label in Name | Pass | Accessible names start with the visible text. Kbd hints follow the label. |
| 2.5.4 Motion Actuation | N/A | None. |
| 2.5.7 Dragging Movements | Pass | Graph panning by drag has alternatives: fit, zoom buttons, and selecting from the pickers. No other drag interactions. |
| 2.5.8 Target Size (Minimum) | Pass | axe `target-size` passes on every route (finding 3). Small inline icon buttons have 24 px spacing. |

### Understandable

| Criterion | Status | Evidence |
|---|---|---|
| 3.1.1 Language of Page | Pass | `<html lang="en">`. |
| 3.1.2 Language of Parts | N/A | English only. |
| 3.2.1 On Focus / 3.2.2 On Input | Pass | Focus never navigates. Selects and filters update the list in place and announce counts. Navigation happens only on activation. |
| 3.2.3 Consistent Navigation / 3.2.4 Consistent Identification | Pass | One shell (top bar, rail) and the shared components across pages. |
| 3.2.6 Consistent Help | Pass | Help (?) sits in the same place in the top bar on every page. |
| 3.3.1 Error Identification / 3.3.3 Error Suggestion | Pass | API errors are mapped to plain-language messages (`errorMessage` in `api.ts`). Field errors are shown next to the field and say how to fix them (e.g. the justification length). |
| 3.3.2 Labels or Instructions | Pass | Every field is labelled, and required formats are hinted ("e.g. Larkspur dev"). |
| 3.3.4 Error Prevention (Legal, Financial, Data) | Pass | Destructive or access-changing actions (revoke, retire, apply bundle, prune) ask for confirmation, and step-up guards the risky ones. |
| 3.3.7 Redundant Entry | Pass | Drafts keep request input, and the cart remembers what was picked. Nothing asks for the same information twice in one flow. |
| 3.3.8 Accessible Authentication (Minimum) | Pass | Sign-in goes through the organisation's IdP and passkeys. Tessera has no password field or cognitive test. The dev sign-in is a picker. |

### Robust

| Criterion | Status | Evidence |
|---|---|---|
| 4.1.2 Name, Role, Value | Pass (axe) / Human | axe `aria-*` and name rules pass everywhere (findings 1–4). That the names read well in NVDA and VoiceOver is for the human pass. |
| 4.1.3 Status Messages | Pass (code) / Human | Toasts render in an `aria-live="polite"` region, and loading states use `role="status"`. To be confirmed with screen readers. |

## Still to do by hand

1. **Screen-reader pass** with NVDA + Firefox and VoiceOver + Safari. Cover sign-in, request,
   inbox approve and review, a side panel, a dialog, and a toast. Record what is announced.
   File any finding as a `bug` labelled `a11y`.
2. Repeat this audit when the UI changes shape: a new layout, a new interaction pattern, or a
   new form type. CI keeps the automated rules from regressing between audits.

## How to run

```bash
cd mvp/frontend
npm ci
npm run test:a11y        # starts the stack with ../run.sh on ports 8610/5610/8611 and a temporary DB
```

The suite raises the per-IP `/api/auth` limits for its own instance only
(`TESSERA_AUTH_RATE_BURST`, `TESSERA_ANON_RATE_BURST`). Every page load calls
`/api/auth/session`, so the default limit of 30 would throttle a browser suite from one
address.
