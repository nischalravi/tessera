@id("no-standing-prod")
@name("No standing privileged access to production")
@severity("high")
forbid (principal, action == Tessera::Action::"reach", resource)
when { principal.type == "human" && resource.privileged && resource has environment
       && resource.environment == "prod" && context.standing && !context.via_jit };

@id("terminated-with-access")
@severity("critical")
forbid (principal, action == Tessera::Action::"reach", resource)
when { principal.status == "terminated" };
