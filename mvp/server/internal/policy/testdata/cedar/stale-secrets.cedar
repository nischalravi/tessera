@id("stale-secrets")
@name("Secrets rotated at least every 90 days")
@severity("medium")
@description("API keys, tokens and service credentials must be rotated within 90 days.")
@type("secret_max_age")
@max_age_days("90")
forbid (principal, action == Tessera::Action::"hold_credential", resource)
when { resource.age_days > 90 && principal.status == "active" };
