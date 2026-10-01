package actions

import (
	"encoding/json"

	"github.com/Inflowenger/go-plugin-sdk/formkit"
	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
	"github.com/venapce/nuclei/internal/forms"
)

// A browse/search button answers by RE-RENDERING the dialog: the host replaces
// the open form with the schema/uischema/data returned here, so a field whose
// options could not exist at compile time (the catalog's profiles, tags, ids)
// becomes a real chooser. The host tells a re-render from a field patch by every
// key being an envelope key, so these builders return only those keys.

// rawCall decodes the flat body a form button posts into a map, for FormData and
// for reading the static "fk" / "value" the button sends.
func rawCall(data []byte) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(data, &m)
	return m
}

// baseForm picks the form to rebuild from the "fk" tag the button sent, so a
// re-render preserves every other field of the form the user is actually on.
func baseForm(call map[string]any) sdkv1.FormBuilder {
	if fk, _ := call["fk"].(string); fk == forms.FormIDSelect {
		return forms.Select()
	}
	return forms.Scan()
}

// singleChooser rebuilds one string field as a drop-down (oneOf).
func singleChooser(call map[string]any, field string, opts []formkit.Option, heading formkit.Notification) any {
	env, err := formkit.Picker(baseForm(call), field, opts, formkit.FormData(call), heading)
	if err != nil {
		// The form could not be rebuilt — fall back to naming the candidates.
		return formkit.Choose(baseForm(call), field, opts, formkit.FormData(call), heading)
	}
	return env
}

// multiChooser rebuilds one array field as a multi-select whose items are an
// enum of the found options. formkit.Choices only does property-level oneOf
// (right for a scalar), so the array case is built here.
func multiChooser(call map[string]any, field string, opts []formkit.Option, heading formkit.Notification) any {
	base := baseForm(call)
	var schema map[string]any
	if err := json.Unmarshal([]byte(base.Jsonschema), &schema); err != nil {
		return formkit.Choose(base, field, opts, formkit.FormData(call), heading)
	}
	props, _ := schema["properties"].(map[string]any)
	prop, _ := props[field].(map[string]any)
	newProp := map[string]any{
		"type":        "array",
		"uniqueItems": true,
		"items":       map[string]any{"type": "string", "oneOf": oneOf(opts)},
	}
	if prop != nil {
		if t, ok := prop["title"]; ok {
			newProp["title"] = t
		}
		if d, ok := prop["description"]; ok {
			newProp["description"] = d
		}
	}
	if props == nil {
		return formkit.Choose(base, field, opts, formkit.FormData(call), heading)
	}
	props[field] = newProp

	envelope := map[string]any{
		"schema":   schema,
		"uischema": base.Jsonui,
		"data":     formkit.FormData(call),
	}
	if heading.Message != "" {
		envelope[formkit.NotifKey] = heading
	}
	return envelope
}

func oneOf(opts []formkit.Option) []any {
	out := make([]any, 0, len(opts))
	for _, o := range opts {
		label := o.Label
		if label == "" {
			label = o.Value
		}
		out = append(out, map[string]any{"const": o.Value, "title": label})
	}
	return out
}
