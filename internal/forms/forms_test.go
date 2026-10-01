package forms

import (
	"encoding/json"
	"testing"

	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
)

// every action form must parse as JSON and must NOT declare a settings property:
// settings is the platform's half of the body, never something the user retypes.
func TestActionFormsAreValidAndSettingsFree(t *testing.T) {
	forms := map[string]sdkv1.FormBuilder{
		"scan":     Scan(),
		"select":   Select(),
		"search":   Search(),
		"update":   Update(),
		"validate": Validate(),
		"workflow": Workflow(),
	}
	for name, fb := range forms {
		var schema map[string]any
		if err := json.Unmarshal([]byte(fb.Jsonschema), &schema); err != nil {
			t.Fatalf("%s: schema does not parse: %v", name, err)
		}
		var ui map[string]any
		if err := json.Unmarshal([]byte(fb.Jsonui), &ui); err != nil {
			t.Fatalf("%s: ui does not parse: %v", name, err)
		}
		props, _ := schema["properties"].(map[string]any)
		if _, bad := props["settings"]; bad {
			t.Errorf("%s: action form declares a settings property", name)
		}
	}
}

func TestSettingsFormParses(t *testing.T) {
	s := Settings()
	var schema map[string]any
	if err := json.Unmarshal([]byte(s.Jsonschema), &schema); err != nil {
		t.Fatalf("settings schema does not parse: %v", err)
	}
	// the SSRF gate must exist and default to blocking.
	props := schema["properties"].(map[string]any)
	gate, ok := props["restrictLocalNetworkAccess"].(map[string]any)
	if !ok {
		t.Fatal("settings form is missing restrictLocalNetworkAccess")
	}
	if gate["default"] != true {
		t.Errorf("restrictLocalNetworkAccess default = %v, want true", gate["default"])
	}
}
