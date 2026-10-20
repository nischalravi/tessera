package store

import (
	"database/sql"
	"time"
)

// Branding (schema/0411_branding.sql): one row per tenant.

// TenantBranding is what a tenant shows on its sign-in and claim pages and in emails.
type TenantBranding struct {
	DisplayName    string
	PrimaryColor   string // #rrggbb
	OnPrimaryColor string // #rrggbb
	LogoType       string // image/png | image/jpeg; "" when there is no logo
	LogoWidth      int
	LogoHeight     int
	LogoSHA256     string
	UpdatedBy      string
	UpdatedAt      time.Time
}

// BrandingLogo is the stored logo image.
type BrandingLogo struct {
	Data   []byte
	Type   string
	Width  int
	Height int
	SHA256 string
}

var (
	brandingGet = tq("tenant_branding.get", `
		SELECT b.display_name, b.primary_color, b.on_primary_color, b.logo_type, b.logo_width, b.logo_height, b.logo_sha256,
			b.updated_by, b.updated_at
		FROM tenant_branding b WHERE b.tenant_id = @tenant`)
	brandingLogo = tq("tenant_branding.logo", `
		SELECT b.logo_data, b.logo_type, b.logo_width, b.logo_height, b.logo_sha256
		FROM tenant_branding b WHERE b.tenant_id = @tenant AND b.logo_data IS NOT NULL`)
	brandingPut = tq("tenant_branding.put", `
		INSERT INTO tenant_branding (tenant_id, display_name, primary_color, on_primary_color, updated_by, updated_at)
		VALUES (@tenant, @display_name, @primary_color, @on_primary_color, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET display_name = @display_name, primary_color = @primary_color,
			on_primary_color = @on_primary_color, updated_by = @updated_by, updated_at = @updated_at`)
	brandingSetLogo = tq("tenant_branding.set_logo", `
		UPDATE tenant_branding SET logo_data = @logo_data, logo_type = @logo_type, logo_width = @logo_width,
			logo_height = @logo_height, logo_sha256 = @logo_sha256
		WHERE tenant_id = @tenant`)
	brandingName = tq("tenant_branding.name", `
		SELECT b.display_name FROM tenant_branding b WHERE b.tenant_id = @tenant`)
)

// Branding returns the tenant's branding, or ErrNotFound when it has not set any.
func (tx *TenantTx) Branding() (*TenantBranding, error) {
	var b TenantBranding
	var lt, ls sql.NullString
	var lw, lh sql.NullInt64
	var at string
	err := tx.queryRow(brandingGet).Scan(&b.DisplayName, &b.PrimaryColor, &b.OnPrimaryColor, &lt, &lw, &lh, &ls, &b.UpdatedBy, &at)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	b.LogoType, b.LogoSHA256, b.LogoWidth, b.LogoHeight = lt.String, ls.String, int(lw.Int64), int(lh.Int64)
	b.UpdatedAt, err = ParseRT(at)
	return &b, err
}

// BrandingLogo returns the stored logo, or ErrNotFound when there is none.
func (tx *TenantTx) BrandingLogo() (*BrandingLogo, error) {
	var l BrandingLogo
	var w, h sql.NullInt64
	err := tx.queryRow(brandingLogo).Scan(&l.Data, &l.Type, &w, &h, &l.SHA256)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	l.Width, l.Height = int(w.Int64), int(h.Int64)
	return &l, nil
}

// BrandName is the tenant's product name for emails, or "" when it has no branding.
func (tx *TenantTx) BrandName() (string, error) {
	var n string
	err := tx.queryRow(brandingName).Scan(&n)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return n, err
}

// PutBranding saves the branding. The logo is replaced when setLogo is true (a nil logo removes it); otherwise the
// stored logo is kept.
func (tx *TenantTx) PutBranding(b *TenantBranding, logo *BrandingLogo, setLogo bool) error {
	if _, err := tx.exec(brandingPut, sql.Named("display_name", b.DisplayName), sql.Named("primary_color", b.PrimaryColor),
		sql.Named("on_primary_color", b.OnPrimaryColor), sql.Named("updated_by", b.UpdatedBy),
		sql.Named("updated_at", RT(b.UpdatedAt))); err != nil {
		return err
	}
	if !setLogo {
		return nil
	}
	var data, typ, sha, w, h any
	if logo != nil {
		data, typ, sha, w, h = logo.Data, logo.Type, logo.SHA256, int64(logo.Width), int64(logo.Height)
	}
	_, err := tx.exec(brandingSetLogo, sql.Named("logo_data", data), sql.Named("logo_type", typ), sql.Named("logo_width", w),
		sql.Named("logo_height", h), sql.Named("logo_sha256", sha))
	return err
}
