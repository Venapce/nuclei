package nuclei

import "testing"

func TestParseSettingsLenientKeys(t *testing.T) {
	c := parseSettings(map[string]any{
		"Templates Dir": "/tmp/nt",
		"rate_limit":    float64(300),
		"allow-code-templates": true,
	})
	if c.TemplatesDir != "/tmp/nt" {
		t.Errorf("TemplatesDir = %q", c.TemplatesDir)
	}
	if c.RateLimit != 300 {
		t.Errorf("RateLimit = %d", c.RateLimit)
	}
	if !c.AllowCodeTemplates {
		t.Error("AllowCodeTemplates should be true")
	}
}

// The one gate that is dangerous when off must default ON when the key is absent.
func TestRestrictLocalNetworkDefaultsOn(t *testing.T) {
	c := parseSettings(map[string]any{})
	if !c.RestrictLocalNetworkAccess {
		t.Error("RestrictLocalNetworkAccess must default to true when unset")
	}
	c2 := parseSettings(map[string]any{"restrictLocalNetworkAccess": false})
	if c2.RestrictLocalNetworkAccess {
		t.Error("operator must be able to turn RestrictLocalNetworkAccess off")
	}
}

func TestGatesDefaultSafe(t *testing.T) {
	c := parseSettings(map[string]any{})
	for name, v := range map[string]bool{
		"AllowIntrusive":     c.AllowIntrusive,
		"AllowCodeTemplates": c.AllowCodeTemplates,
		"AllowDAST":          c.AllowDAST,
		"AllowHeadless":      c.AllowHeadless,
	} {
		if v {
			t.Errorf("%s must default to false (safe)", name)
		}
	}
}
