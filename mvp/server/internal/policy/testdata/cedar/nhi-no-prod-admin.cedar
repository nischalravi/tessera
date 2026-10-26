@id("nhi-no-prod-admin")
@name("Non-human identities may not hold prod admin")
@severity("high")
@description("Service accounts and agents should use narrowly scoped roles, never admin on prod.")
@type("no_standing_access")
forbid (principal, action == Tessera::Action::"reach", resource)
when { (["service", "ai_agent"].contains(principal.type) && principal.status == "active") && (resource.privileged == true && (resource has environment && resource.environment == "prod")) && (context.standing) };
