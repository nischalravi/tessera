@id("no-standing-prod-admin")
@name("No standing admin on prod")
@severity("high")
@description("Privileged permissions on production resources must be obtained just-in-time. Access reached only through a JIT grant does not violate this policy.\n")
@type("no_standing_access")
forbid (principal, action == Tessera::Action::"reach", resource)
when { (principal.type == "human" && principal.status == "active") && (resource.privileged == true && (resource has environment && resource.environment == "prod")) && (context.standing) };
