@id("support-bot")
@agent("entra:7f3c")
permit (principal == Tessera::Agent::"entra:7f3c", action == Tessera::Action::"reach", resource)
when { ["list", "read"].contains(context.action_class) && resource.tags.contains("support")
       && context.system == "aws" };
