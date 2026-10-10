package api

import (
	_ "embed"
	"net/http"
)

// The OpenAPI document and the Swagger UI / ReDoc pages are the ones the
// original FastAPI app generated, served verbatim so tooling built against
// them keeps working.

//go:embed openapi.json
var openAPIDoc []byte

//go:embed docs_swagger.html
var swaggerHTML string

//go:embed docs_redoc.html
var redocHTML string

const oauth2RedirectHTML = `<!doctype html><html lang="en-US"><head><title>Swagger UI: OAuth2 Redirect</title></head>
<body><script>
'use strict';
function run () {
    var oauth2 = window.opener.swaggerUIRedirectOauth2;
    var sentState = oauth2.state;
    var redirectUrl = oauth2.redirectUrl;
    var isValid, qp, arr;
    if (/code|token|error/.test(window.location.hash)) { qp = window.location.hash.substring(1).replace('?', '&'); }
    else { qp = location.search.substring(1); }
    arr = qp.split("&");
    arr.forEach(function (v,i,_arr) { _arr[i] = '"' + v.replace('=', '":"') + '"';});
    qp = qp ? JSON.parse('{' + arr.join() + '}', function (key, value) { return key === "" ? value : decodeURIComponent(value); }) : {};
    isValid = qp.state === sentState;
    if ((oauth2.auth.schema.get("flow") === "accessCode" || oauth2.auth.schema.get("flow") === "authorizationCode" || oauth2.auth.schema.get("flow") === "authorization_code") && !oauth2.auth.code) {
        if (!isValid) { oauth2.errCb({ authId: oauth2.auth.name, source: "auth", level: "warning", message: "Authorization may be unsafe, passed state was changed in server. The passed state wasn't returned from auth server." }); }
        if (qp.code) { delete oauth2.state; oauth2.auth.code = qp.code; oauth2.callback({auth: oauth2.auth, redirectUrl: redirectUrl}); }
        else { let oauthErrorMsg; if (qp.error) { oauthErrorMsg = "["+qp.error+"]: " + (qp.error_description ? qp.error_description+ ". " : "no accessCode received from the server. ") + (qp.error_uri ? "More info: "+qp.error_uri : ""); }
            oauth2.errCb({ authId: oauth2.auth.name, source: "auth", level: "error", message: oauthErrorMsg || "[Authorization failed]: no accessCode received from the server." }); }
    } else { oauth2.callback({auth: oauth2.auth, token: qp, isValid: isValid, redirectUrl: redirectUrl}); }
    window.close();
}
if (document.readyState !== 'loading') { run(); } else { document.addEventListener('DOMContentLoaded', function () { run(); }); }
</script></body></html>`

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

func (s *Server) openAPI(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	return rawJSON(openAPIDoc), nil
}

func (s *Server) swaggerUI(w http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	writeHTML(w, swaggerHTML)
	return nil, nil
}

func (s *Server) swaggerRedirect(w http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	writeHTML(w, oauth2RedirectHTML)
	return nil, nil
}

func (s *Server) redoc(w http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	writeHTML(w, redocHTML)
	return nil, nil
}
