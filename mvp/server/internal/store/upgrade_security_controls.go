package store

import "context"

// upgradeSecurityControls adds the columns of issues #510 (help-desk risk signal submitter and dismissal) and #512
// (queue_schedules.paused_until) and #522 (api_clients.approved_by) to a SQLite database created before them. Postgres does this in migration 0770.
func (d *DB) upgradeSecurityControls(ctx context.Context) error {
	if err := d.addMissingColumns(ctx, "helpdesk_idp_risks", [][2]string{
		{"submitted_by", "TEXT NOT NULL DEFAULT ''"}, {"submitted_by_user", "TEXT NOT NULL DEFAULT ''"},
		{"dismissed_at", "TEXT NOT NULL DEFAULT ''"}, {"dismissed_by", "TEXT NOT NULL DEFAULT ''"},
		{"dismissed_by_user", "TEXT NOT NULL DEFAULT ''"}, {"dismiss_reason", "TEXT NOT NULL DEFAULT ''"}}); err != nil {
		return err
	}
	if err := d.addMissingColumns(ctx, "api_clients", [][2]string{{"approved_by", "TEXT NOT NULL DEFAULT ''"}}); err != nil {
		return err
	}
	return d.addMissingColumns(ctx, "queue_schedules", [][2]string{{"paused_until", "TEXT NOT NULL DEFAULT ''"}})
}
