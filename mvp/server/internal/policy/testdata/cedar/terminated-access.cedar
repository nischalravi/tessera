@id("terminated-access")
@name("Leavers retain no access")
@severity("critical")
@description("Terminated identities must not have any effective permission in any system.")
@type("terminated_with_access")
forbid (principal, action == Tessera::Action::"reach", resource)
when { principal.status == "terminated" };
