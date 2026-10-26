@id("secret-max-age")
@severity("medium")
forbid (principal, action == Tessera::Action::"hold_credential", resource)
when { resource.age_days > 90 };

@id("nhi-ownership")
@severity("high")
forbid (principal, action == Tessera::Action::"exist", resource)
when { ["service", "ai_agent"].contains(principal.type) && principal.status == "active"
       && !(principal has owner) };
