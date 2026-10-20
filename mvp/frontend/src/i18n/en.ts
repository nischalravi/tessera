/**
 * English messages for the public pages (claim, register, renew). Keys are stable ids; values may use
 * {name} placeholders. Other languages are added as a file with the same keys (see index.ts): a missing
 * key falls back to English, so a partial translation never shows an empty label.
 */
export const en = {
  "brand.default": "Tessera",

  // shared
  "common.loading": "Loading…",
  "common.sending": "Sending…",
  "common.generic_error": "Something went wrong. Try again.",
  "common.progress": "Progress",
  "common.step_done": "Done: ",
  "common.step_current": "Current step: ",
  "common.step_later": "Later: ",

  // claim: steps
  "claim.step.verify_contact": "Confirm your email",
  "claim.step.verify_identity": "Verify your identity",
  "claim.step.existing_account": "Existing account",
  "claim.step.credential": "Choose how you sign in",
  "claim.step.complete": "Done",

  "claim.population.visitor": "a visitor",
  "claim.population.contractor": "a contractor",
  "claim.population.volunteer": "a volunteer",
  "claim.population.partner": "a partner",
  "claim.population.default": "a guest",

  "claim.opening": "Opening your invitation…",
  "claim.title": "Claim your account",

  // claim: banners
  "claim.banner.failed": "We could not finish your sign-in. It may not have been strong enough, or it was for a different account. Try again.",
  "claim.banner.recovery": "You are recovering your account. We check who you are again before a new sign-in is set up.",
  "claim.banner.cooling_off": "Your new sign-in is saved. Because your account has privileged access it becomes active after a 24 hour wait. Everyone on record for your account has been told.",
  "claim.banner.continue": "That sign-in was not added to this invitation. You can carry on and set up a new sign-in below.",

  // claim: link did not work
  "claim.check.title": "Check your link",
  "claim.check.body": "This link did not work. It may have expired or been used already, or it may have been copied incompletely. Open the link in your invitation email again, or ask for a new one.",
  "claim.check.email": "Your email address",
  "claim.check.note": "We send a new link only if an invitation exists for this address, and we do not say whether one does.",
  "claim.check.send": "Send me a new link",

  // claim: verify contact
  "claim.verify.title": "Hello {name}, confirm your email",
  "claim.verify.intro": "{sponsor} invited you to {tenant} as {population}, until {date}. We will send a six-digit code to the email address they gave us to check it is yours.",
  "claim.verify.send": "Send me a code",
  "claim.verify.code": "Six-digit code",
  "claim.verify.help": "The code works for ten minutes and five tries. {sent}",
  "claim.verify.check": "Check the code",
  "claim.verify.resend": "Send a new code",

  // claim: verify identity
  "claim.idv.title": "Your identity needs to be verified",
  "claim.idv.intro": "The access in this invitation needs a stronger identity check than an email code. There are two ways to do it.",
  "claim.idv.agent_title": "Visit a proofing agent",
  "claim.idv.agent_body": "Bring a government-issued photo ID to the proofing desk named in your invitation, or ask {sponsor} where it is. The agent checks your ID against you in person and finishes this step. You do not need to do anything else on this page.",
  "claim.idv.online_title": "Verify online",
  "claim.idv.online_body": "Online verification with a document and a selfie is not available yet. Your sponsor or your organization will contact you when it is.",
  "claim.idv.keep_open": "Your invitation stays open. You can close this page and come back to the same link later.",

  // claim: existing account
  "claim.existing.title": "Do you already have an account with {tenant}?",
  "claim.existing.body": "Everyone is asked this. If you say yes, you sign in with that account first, so this invitation can be added to it. If you say no, you set up a new sign-in.",
  "claim.existing.no": "No, I do not",
  "claim.existing.yes": "Yes, I do",
  "claim.existing.yes_note": "Next you sign in with your existing account, using a passkey if you have one.",
  "claim.existing.signin": "Sign in",
  "claim.existing.continue": "Continue",

  // claim: terms and consent
  "claim.terms.title": "Before you sign in",
  "claim.terms.version": "(version {version})",
  "claim.terms.text": "{title} text",
  "claim.terms.accept_label": "I have read and accept {title}",
  "claim.terms.consent_legend": "What your home organization shares with {tenant}",
  "claim.terms.needed": " (needed)",
  "claim.terms.submit": "Accept and continue",
  "claim.terms.continue": "Continue",

  // claim: credential
  "claim.credential.title": "Choose how you sign in",
  "claim.credential.pending": "Your organization will finish setting up your sign-in. We will email you when it is ready.",
  "claim.credential.pending_short": "Your organization will finish setting up your sign-in.",
  "claim.credential.stays_open": "Your invitation stays open. You can close this page.",
  "claim.credential.body": "Next you sign in with your organization's login, using a passkey. That sign-in is what you use from now on.",
  "claim.credential.go": "Continue to sign-in",

  // claim: waiting / done
  "claim.waiting.title": "Almost there",
  "claim.done.title": "You are all set, {name}",
  "claim.done.title_cooling": "Thank you, {name}",
  "claim.done.ready": "Your sign-in for {tenant} is ready. Use the same login whenever you are asked to sign in.",
  "claim.done.cooling": "Your new sign-in for {tenant} will be ready after the 24 hour wait.",
  "claim.done.access": "Your access runs until {date}. {sponsor} has been told. You can close this page.",
  "claim.done.recovery_title": "If you lose your sign-in",
  "claim.done.recovery_body": "Ask {sponsor} or the help desk to start recovery. You will prove who you are again before a new sign-in is set up; asking is never enough on its own.",

  // register
  "register.title": "Register as a guest",
  "register.intro": "Tell us who you are and who invited you. Nothing is created until they approve.",
  "register.given_name": "First name",
  "register.family_name": "Last name",
  "register.email": "Email",
  "register.purpose": "Why do you need access?",
  "register.until": "Until",
  "register.sponsor_legend": "Your sponsor",
  "register.mode_search": "Search by name",
  "register.mode_code": "I have a code",
  "register.sponsor_name": "Sponsor's name",
  "register.sponsor_help": "Type at least two letters.",
  "register.sponsor_results": "Matching sponsors",
  "register.sponsor_code": "Sponsor code",
  "register.submit": "Ask my sponsor",
  "register.sent_suffix": "If your sponsor approves, we will send you a link to set up your sign-in.",
  "register.error.pick_sponsor": "Pick the person who will sponsor you from the search results.",
  "register.error.enter_code": "Enter the code your sponsor gave you.",
  "register.results_count": "{count} sponsors found. Choose one.",
  "register.results_none": "No sponsor matches that name.",
  "register.sent_title": "Check your email",

  // renew
  "renew.title": "Ask for your access to be renewed",
  "renew.nolink": "Open the link from your reminder email to ask for a renewal. If it does not work, ask your sponsor directly.",
  "renew.body": "Your access is about to end. Your sponsor decides whether to renew it; this sends them a request.",
  "renew.submit": "Request renewal",
  "renew.sent": "We have received your request. If your sponsor agrees, they will renew your access.",
} as const;

export type MessageKey = keyof typeof en;
