# Security headers for the static SPA locations (add_header is not inherited once a location sets its own,
# so every static location includes this file). The API sets its own headers on proxied responses.
#
# CSP: the Vite build emits one external module script and one stylesheet, no inline script. React sets
# style="..." attributes, which need style-src-attr (attributes only; <style> elements stay blocked).
# connect-src 'self' because the SPA only talks to the same origin (/api, /public, /t).
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy no-referrer always;
add_header X-Frame-Options DENY always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
# Empty unless the request arrived over https (see $tessera_hsts in tessera.conf.template); nginx omits
# a header whose value is empty.
add_header Strict-Transport-Security $tessera_hsts always;
