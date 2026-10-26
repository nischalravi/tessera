@id("ai-agents-no-pii")
@name("AI agents may not access PII")
@severity("critical")
@description("AI agents must not be able to reach any resource tagged pii, directly or through role inheritance.\n")
@type("forbidden_access")
forbid (principal, action == Tessera::Action::"reach", resource)
when { (principal.type == "ai_agent" && principal.status == "active") && (resource.tags.containsAny(["pii"])) };
