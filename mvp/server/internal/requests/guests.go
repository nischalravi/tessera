package requests

import (
	"errors"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Requests by guests (design §9.3, issue #75 / GU-12): a guest may request
// the catalog items that name their population; approval goes to their
// sponsor first, then to the resource owner; an item that needs identity
// assurance IAL 2 (privileged or high risk, the sponsor policy's rule for
// bundles) is refused for a guest who has not reached it.
//
// Seam: the step-up claim that raises a guest's IAL (identity verification,
// GU-7/GU-8) is not built. The refusal carries the code step_up_claim_required;
// once the step-up can run, the client starts it on that code and the guest
// asks again. Nothing here starts it.

// SensitiveMinIAL is the identity assurance a privileged or high-risk item
// needs of a guest (the sponsor policy's sensitive_bundle_min_ial).
const SensitiveMinIAL = 2

// GuestPopulations are the populations an item may be opened to.
var GuestPopulations = []string{store.PopVisitor, store.PopContractor, store.PopVolunteer, store.PopPartner}

var affPopulation = map[string]string{store.AffGuestVisitor: store.PopVisitor, store.AffContractor: store.PopContractor,
	store.AffVolunteer: store.PopVolunteer, store.AffPartner: store.PopPartner}

// GuestPopulationsOf returns the guest populations a person belongs to now
// (an active affiliation of a guest kind); nil for staff. A person who also
// comes from the HR or student system is staff.
func GuestPopulationsOf(tx *store.TenantTx, identityID int64) ([]string, error) {
	affs, err := tx.AffiliationsFor(identityID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range affs {
		if a.Status != store.AffActive {
			continue
		}
		if a.Source == store.AffSourceHRIS || a.Source == store.AffSourceSIS {
			return nil, nil
		}
		if p, ok := affPopulation[a.Type]; ok && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// sensitive reports whether an item needs IAL 2 of a guest.
func sensitive(it *store.CatalogItem, g *store.Group) bool { return it.Risk == "high" || g.Privileged }

// guestChecks applies the rules for a guest beneficiary: the item is open to
// their population and their assurance is enough. A person who is not a guest
// passes.
func guestChecks(tx *store.TenantTx, ben *store.Identity, it *store.CatalogItem, g *store.Group) error {
	pops, err := GuestPopulationsOf(tx, ben.ID)
	if err != nil || len(pops) == 0 {
		return err
	}
	open, err := tx.CatalogPopulations(it.ID)
	if err != nil {
		return err
	}
	name := g.System + ":" + g.Name
	if !slices.ContainsFunc(open, func(p *store.CatalogPopulation) bool { return slices.Contains(pops, p.Population) }) {
		return refuse(409, "not_eligible", "%s is not open to guests of %s's population", name, ben.Name)
	}
	if !sensitive(it, g) {
		return nil
	}
	ial := 0
	if a, err := tx.IdentityAssurance(ben.ID); err == nil {
		ial = a.IAL
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if ial < SensitiveMinIAL {
		return refuse(403, "step_up_claim_required", "%s needs identity assurance IAL %d; %s has IAL %d, so a step-up claim comes first",
			name, SensitiveMinIAL, ben.Name, ial)
	}
	return nil
}

// sponsorOf is the sponsor a guest's request goes to first: the sponsor of
// the live sponsorship that ends last. ok is false for a person with none.
func sponsorOf(tx *store.TenantTx, guest int64) (id int64, ok bool, err error) {
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
	if err != nil {
		return 0, false, err
	}
	var last *store.Sponsorship
	for _, s := range all {
		if s.Live() && (last == nil || s.EndsAt.After(last.EndsAt)) {
			last = s
		}
	}
	if last == nil {
		return 0, false, nil
	}
	return last.SponsorIdentityID, true, nil
}

// guestKinds is the approval route of a guest's request: the sponsor first,
// then the item's own stages without the manager (a guest has none); an item
// left on the default decider stage goes to its owner when it has one.
func guestKinds(kinds []string, it *store.CatalogItem) []string {
	rest := slices.DeleteFunc(slices.Clone(kinds), func(k string) bool { return k == store.StageManager || k == store.StageSponsor })
	if len(rest) == 1 && rest[0] == store.StageDecider && it.OwnerIdentityID != nil {
		rest = []string{store.StageOwner}
	}
	out := append([]string{store.StageSponsor}, rest...)
	if len(out) > MaxStages {
		out = out[:MaxStages]
	}
	return out
}
