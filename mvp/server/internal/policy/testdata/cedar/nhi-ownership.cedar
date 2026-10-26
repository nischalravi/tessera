@id("nhi-ownership")
@name("Every NHI and AI agent has an active owner")
@severity("high")
@description("Service accounts, API keys and AI agents must have an owner who is a current employee.")
@type("nhi_ownership")
forbid (principal, action == Tessera::Action::"exist", resource)
when { ["service", "ai_agent"].contains(principal.type) && principal.status == "active" && !(principal has owner && principal.owner.status == "active") };
