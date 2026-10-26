@id("payments-analyst-birthright")
@role("payments-analyst")
permit (principal is Tessera::Identity, action == Tessera::Action::"birthright",
        resource == Tessera::Role::"payments-analyst")
when { principal.status == "active" && principal has department && ["finance"].contains(principal.department)
       && ["human"].contains(principal.type) && principal.attrs has cost_center && principal.attrs.cost_center == "4410" };
