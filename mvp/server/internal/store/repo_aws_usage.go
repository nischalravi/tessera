package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AWS usage (schema/0915_aws_usage.sql). Every statement binds the tenant.

const awsUsageCols = `u.connector_id, u.principal_arn, u.action, u.resource_scope, u.day, u.source, u.count, u.last_seen`

var (
	// CloudTrail rows add: an object is read once (the cursor moves in the same transaction), so a day's count is a sum.
	awsUsageAdd = tq("aws_usage_daily.add", `
		INSERT INTO aws_usage_daily (tenant_id, connector_id, principal_arn, action, resource_scope, day, source, count, last_seen)
		VALUES (@tenant, @connector_id, @principal_arn, @action, @resource_scope, @day, @source, @count, @last_seen)
		ON CONFLICT (tenant_id, connector_id, principal_arn, action, resource_scope, day, source)
		DO UPDATE SET count = aws_usage_daily.count + excluded.count,
			last_seen = CASE WHEN excluded.last_seen > aws_usage_daily.last_seen THEN excluded.last_seen ELSE aws_usage_daily.last_seen END`)
	// Access Advisor rows replace: the service reports a last-accessed time, not events.
	awsUsageSet = tq("aws_usage_daily.set", `
		INSERT INTO aws_usage_daily (tenant_id, connector_id, principal_arn, action, resource_scope, day, source, count, last_seen)
		VALUES (@tenant, @connector_id, @principal_arn, @action, @resource_scope, @day, @source, @count, @last_seen)
		ON CONFLICT (tenant_id, connector_id, principal_arn, action, resource_scope, day, source)
		DO UPDATE SET count = excluded.count, last_seen = excluded.last_seen`)
	awsUsageList = tq("aws_usage_daily.list", `
		SELECT `+awsUsageCols+` FROM aws_usage_daily u
		WHERE u.tenant_id = @tenant AND (@connector_id = '' OR u.connector_id = @connector_id)
			AND (@principal_arn = '' OR u.principal_arn = @principal_arn) AND u.day >= @since
		ORDER BY u.principal_arn, u.action, u.resource_scope, u.day, u.source LIMIT @limit`)
	awsUsagePrune = tq("aws_usage_daily.prune", `
		DELETE FROM aws_usage_daily WHERE tenant_id = @tenant AND day < @before`)

	awsUsageStateGet = tq("aws_usage_state.get", `
		SELECT s.connector_id, s.source, s.cursor, s.covered_from, s.covered_to, s.s3_data_events, s.updated_at
		FROM aws_usage_state s WHERE s.tenant_id = @tenant AND s.connector_id = @connector_id AND s.source = @source`)
	awsUsageStateList = tq("aws_usage_state.list", `
		SELECT s.connector_id, s.source, s.cursor, s.covered_from, s.covered_to, s.s3_data_events, s.updated_at
		FROM aws_usage_state s WHERE s.tenant_id = @tenant AND (@connector_id = '' OR s.connector_id = @connector_id)
		ORDER BY s.connector_id, s.source`)
	awsUsageStatePut = tq("aws_usage_state.put", `
		INSERT INTO aws_usage_state (tenant_id, connector_id, source, cursor, covered_from, covered_to, s3_data_events, updated_at)
		VALUES (@tenant, @connector_id, @source, @cursor, @covered_from, @covered_to, @s3_data_events, @updated_at)
		ON CONFLICT (tenant_id, connector_id, source)
		DO UPDATE SET cursor = excluded.cursor, covered_from = excluded.covered_from, covered_to = excluded.covered_to,
			s3_data_events = excluded.s3_data_events, updated_at = excluded.updated_at`)

	awsUsageGapPut = tq("aws_usage_gaps.put", `
		INSERT INTO aws_usage_gaps (tenant_id, connector_id, source, ref, code, detail, day, recorded_at)
		VALUES (@tenant, @connector_id, @source, @ref, @code, @detail, @day, @recorded_at)
		ON CONFLICT (tenant_id, connector_id, source, ref)
		DO UPDATE SET code = excluded.code, detail = excluded.detail, day = excluded.day, recorded_at = excluded.recorded_at`)
	awsUsageGapList = tq("aws_usage_gaps.list", `
		SELECT g.connector_id, g.source, g.ref, g.code, g.detail, g.day, g.recorded_at FROM aws_usage_gaps g
		WHERE g.tenant_id = @tenant AND (@connector_id = '' OR g.connector_id = @connector_id)
		ORDER BY g.recorded_at DESC, g.ref LIMIT @limit`)
	awsUsageGapClear = tq("aws_usage_gaps.clear", `
		DELETE FROM aws_usage_gaps WHERE tenant_id = @tenant AND connector_id = @connector_id AND source = @source AND ref = @ref`)
	awsUsageGapPrune = tq("aws_usage_gaps.prune", `
		DELETE FROM aws_usage_gaps WHERE tenant_id = @tenant AND recorded_at < @before`)
)

func (u *AWSUsageDay) validate() error {
	if u.ConnectorID == "" || u.PrincipalARN == "" || u.Action == "" || u.ResourceScope == "" {
		return errors.New("store: aws usage row needs a connector, principal, action and resource scope")
	}
	if _, err := time.Parse("2006-01-02", u.Day); err != nil {
		return fmt.Errorf("store: aws usage day %q is not YYYY-MM-DD", u.Day)
	}
	if u.Count < 0 {
		return errors.New("store: aws usage count is negative")
	}
	return nil
}

func (tx *TenantTx) putUsage(s tstmt, u *AWSUsageDay) error {
	if err := u.validate(); err != nil {
		return err
	}
	_, err := tx.exec(s, sql.Named("connector_id", u.ConnectorID), sql.Named("principal_arn", u.PrincipalARN),
		sql.Named("action", u.Action), sql.Named("resource_scope", u.ResourceScope), sql.Named("day", u.Day),
		sql.Named("source", u.Source), sql.Named("count", u.Count), sql.Named("last_seen", RT(u.LastSeen)))
	return err
}

// AddAWSUsage adds u's count to the row of its key, creating it: for sources
// that report events. The caller moves the cursor in the same transaction, so
// an object is never counted twice.
func (tx *TenantTx) AddAWSUsage(u *AWSUsageDay) error { return tx.putUsage(awsUsageAdd, u) }

// SetAWSUsage replaces the row of u's key: for sources that report a last-used
// time and not events (Access Advisor).
func (tx *TenantTx) SetAWSUsage(u *AWSUsageDay) error { return tx.putUsage(awsUsageSet, u) }

func scanAWSUsage(s scanner) (*AWSUsageDay, error) {
	var u AWSUsageDay
	var seen string
	if err := s.Scan(&u.ConnectorID, &u.PrincipalARN, &u.Action, &u.ResourceScope, &u.Day, &u.Source, &u.Count, &seen); err != nil {
		return nil, err
	}
	var err error
	u.LastSeen, err = ParseRT(seen)
	return &u, err
}

// AWSUsage lists usage rows from day since (YYYY-MM-DD) on, ordered by
// principal, action, scope and day. connectorID and principalARN "" match all.
func (tx *TenantTx) AWSUsage(connectorID, principalARN, since string, limit int) ([]*AWSUsageDay, error) {
	if limit <= 0 || limit > 100000 {
		limit = 100000
	}
	return collect(tx, scanAWSUsage, awsUsageList, sql.Named("connector_id", connectorID), sql.Named("principal_arn", principalARN),
		sql.Named("since", since), sql.Named("limit", limit))
}

// PruneAWSUsage deletes the tenant's usage rows of days before day (YYYY-MM-DD).
func (tx *TenantTx) PruneAWSUsage(before string) (int64, error) {
	res, err := tx.exec(awsUsagePrune, sql.Named("before", before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanAWSUsageState(s scanner) (*AWSUsageState, error) {
	var st AWSUsageState
	var cur, at string
	if err := s.Scan(&st.ConnectorID, &st.Source, &cur, &st.CoveredFrom, &st.CoveredTo, &st.S3DataEvents, &at); err != nil {
		return nil, err
	}
	st.Cursor = json.RawMessage(cur)
	var err error
	st.UpdatedAt, err = ParseRT(at)
	return &st, err
}

// AWSUsageState returns a connector's state for a source, or ErrNotFound.
func (tx *TenantTx) AWSUsageState(connectorID, source string) (*AWSUsageState, error) {
	return one(tx, scanAWSUsageState, awsUsageStateGet, sql.Named("connector_id", connectorID), sql.Named("source", source))
}

// AWSUsageStates lists the states of a connector (every connector's with "").
func (tx *TenantTx) AWSUsageStates(connectorID string) ([]*AWSUsageState, error) {
	return collect(tx, scanAWSUsageState, awsUsageStateList, sql.Named("connector_id", connectorID))
}

// PutAWSUsageState creates or replaces a connector's state for a source.
func (tx *TenantTx) PutAWSUsageState(st *AWSUsageState) error {
	cur := st.Cursor
	if len(cur) == 0 {
		cur = json.RawMessage("{}")
	}
	if len(cur) > MaxAWSUsageCursorBytes {
		return errors.New("store: aws usage cursor is too large")
	}
	switch st.S3DataEvents {
	case "":
		st.S3DataEvents = AWSDataEventsUnknown
	case AWSDataEventsEnabled, AWSDataEventsDisabled, AWSDataEventsUnknown:
	default:
		return fmt.Errorf("store: unknown s3 data events state %q", st.S3DataEvents)
	}
	_, err := tx.exec(awsUsageStatePut, sql.Named("connector_id", st.ConnectorID), sql.Named("source", st.Source),
		sql.Named("cursor", string(cur)), sql.Named("covered_from", st.CoveredFrom), sql.Named("covered_to", st.CoveredTo),
		sql.Named("s3_data_events", st.S3DataEvents), sql.Named("updated_at", RT(st.UpdatedAt)))
	return err
}

// PutAWSUsageGap records a gap (one row per connector, source and ref; recording it again refreshes it).
func (tx *TenantTx) PutAWSUsageGap(g *AWSUsageGap) error {
	_, err := tx.exec(awsUsageGapPut, sql.Named("connector_id", g.ConnectorID), sql.Named("source", g.Source), sql.Named("ref", g.Ref),
		sql.Named("code", g.Code), sql.Named("detail", g.Detail), sql.Named("day", g.Day), sql.Named("recorded_at", RT(g.RecordedAt)))
	return err
}

// ClearAWSUsageGap removes a gap that no longer applies; a missing one is not an error.
func (tx *TenantTx) ClearAWSUsageGap(connectorID, source, ref string) error {
	_, err := tx.exec(awsUsageGapClear, sql.Named("connector_id", connectorID), sql.Named("source", source), sql.Named("ref", ref))
	return err
}

func scanAWSUsageGap(s scanner) (*AWSUsageGap, error) {
	var g AWSUsageGap
	var at string
	if err := s.Scan(&g.ConnectorID, &g.Source, &g.Ref, &g.Code, &g.Detail, &g.Day, &at); err != nil {
		return nil, err
	}
	var err error
	g.RecordedAt, err = ParseRT(at)
	return &g, err
}

// AWSUsageGaps lists gaps newest first (every connector's with "").
func (tx *TenantTx) AWSUsageGaps(connectorID string, limit int) ([]*AWSUsageGap, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	return collect(tx, scanAWSUsageGap, awsUsageGapList, sql.Named("connector_id", connectorID), sql.Named("limit", limit))
}

// PruneAWSUsageGaps deletes the tenant's gaps recorded before the given time.
func (tx *TenantTx) PruneAWSUsageGaps(before time.Time) (int64, error) {
	res, err := tx.exec(awsUsageGapPrune, sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
