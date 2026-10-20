package guestlife

import (
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ValidateSettings checks a tenant's lifecycle settings and puts the reminder
// days in order (largest first, no duplicates).
func ValidateSettings(set *store.GuestLifecycleSettings) error {
	days := slices.Clone(set.SponsorReminderDays)
	slices.SortFunc(days, func(a, b int) int { return b - a })
	days = slices.Compact(days)
	switch {
	case len(days) > 5:
		return refuse(422, "invalid_reminder_days", "at most 5 reminder thresholds")
	case slices.ContainsFunc(days, func(d int) bool { return d < 1 || d > 365 }):
		return refuse(422, "invalid_reminder_days", "reminder thresholds are 1 to 365 days before the end")
	case set.GuestReminderDays < 0 || set.GuestReminderDays > 365:
		return refuse(422, "invalid_guest_reminder_days", "the guest reminder is 0 (off) to 365 days before the end")
	case set.TransferDeadlineDays < 1 || set.TransferDeadlineDays > 90:
		return refuse(422, "invalid_transfer_deadline", "the transfer deadline is 1 to 90 days")
	case set.OnSponsorDeparture != "end" && set.OnSponsorDeparture != "suspend":
		return refuse(422, "invalid_on_sponsor_departure", "on_sponsor_departure is end or suspend")
	case set.ConversionDualStatus != "end" && set.ConversionDualStatus != "sponsor_confirms":
		return refuse(422, "invalid_conversion_dual_status", "conversion_dual_status is end or sponsor_confirms")
	case set.RetentionDays < 1 || set.RetentionDays > 36500 || set.RetentionDaysVisitor < 1 || set.RetentionDaysVisitor > 36500:
		return refuse(422, "invalid_retention", "retention is 1 to 36500 days")
	}
	for _, p := range []string{store.PopVisitor, store.PopContractor, store.PopVolunteer, store.PopPartner} {
		if g, ok := set.GraceDays[p]; !ok || g < 0 || g > 365 {
			return refuse(422, "invalid_grace", "grace_days needs visitor, contractor, volunteer and partner, each 0 to 365 days")
		}
	}
	set.SponsorReminderDays = days
	return nil
}

// PutSettings saves the tenant's settings, audited.
func PutSettings(tx *store.TenantTx, set store.GuestLifecycleSettings, by Actor, now time.Time) (store.GuestLifecycleSettings, error) {
	if err := ValidateSettings(&set); err != nil {
		return set, err
	}
	u := ""
	if by.UserID != uuid.Nil {
		u = by.UserID.String()
	}
	if err := tx.PutGuestLifecycleSettings(set, u, now); err != nil {
		return set, err
	}
	out, err := tx.GuestLifecycleSettings()
	if err != nil {
		return out, err
	}
	return out, tx.Audit(now, by.Display, "guestlife.settings.update", ojson.Object{kv("sponsor_reminder_days", out.SponsorReminderDays),
		kv("guest_reminder_days", out.GuestReminderDays), kv("transfer_deadline_days", out.TransferDeadlineDays),
		kv("on_sponsor_departure", out.OnSponsorDeparture), kv("conversion_dual_status", out.ConversionDualStatus),
		kv("grace_days", ojson.Object{kv("visitor", out.GraceDays[store.PopVisitor]), kv("contractor", out.GraceDays[store.PopContractor]),
			kv("volunteer", out.GraceDays[store.PopVolunteer]), kv("partner", out.GraceDays[store.PopPartner])}),
		kv("retention_days", out.RetentionDays), kv("retention_days_visitor", out.RetentionDaysVisitor),
		kv("keep_rematch_hashes", out.KeepRematchHashes)})
}
