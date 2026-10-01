package actions

import (
	"fmt"
	"strings"

	"github.com/Inflowenger/go-plugin-sdk/formkit"
	"github.com/Inflowenger/go-plugin-sdk/sdkv1"
	"github.com/venapce/nuclei/internal/nuclei"
)

// Ping is the settings validator (RequiredParams.SubmitHandler) and the manual
// run-button target. It reports catalog health and which gates are open.
func Ping(r sdkv1.Request) sdkv1.Response {
	settings := metaSettings(r.Data)
	sc := scannerFor(settings)
	defer sc.Close()

	h := sc.Health(ctxOf())
	if !h.OK {
		msg := h.Message
		if msg == "" {
			msg = "nuclei is not ready"
		}
		return sdkv1.Response{Error: msg}
	}
	return sdkv1.Response{Data: map[string]any{
		"ok":               true,
		"engineVersion":    h.EngineVersion,
		"templatesDir":     h.TemplatesDir,
		"templatesVersion": h.TemplatesVersion,
		"templateCount":    h.TemplateCount,
		"codeTemplates":    h.CodeTemplates,
		"intrusive":        h.Intrusive,
	}}
}

// Profiles is the Browse button on the profile field: it rebuilds that field as a
// drop-down of the catalog's named profiles.
func Profiles(r sdkv1.Request) any {
	call := rawCall(r.Data)
	sc := scannerFor(metaSettings(r.Data))
	defer sc.Close()

	names, err := sc.Profiles(ctxOf())
	if err != nil {
		return formkit.Failure("could not read profiles: %s", err).About("profile").Patch(nil)
	}
	if len(names) == 0 {
		return formkit.Warning("no profiles found — run Update Templates first").About("profile").Patch(nil)
	}
	opts := make([]formkit.Option, 0, len(names))
	for _, n := range names {
		opts = append(opts, formkit.Option{Value: n, Label: n})
	}
	return singleChooser(call, "profile", opts, formkit.Success("pick a profile (%d available)", len(names)))
}

// Tags is the Browse-tags button: it rebuilds the tags field as a multi-select of
// the catalog's most-used tags.
func Tags(r sdkv1.Request) any {
	call := rawCall(r.Data)
	sc := scannerFor(metaSettings(r.Data))
	defer sc.Close()

	tags, err := sc.Tags(ctxOf(), 60)
	if err != nil {
		return formkit.Failure("could not read tags: %s", err).About("tags").Patch(nil)
	}
	if len(tags) == 0 {
		return formkit.Warning("no tag stats available — run Update Templates first").About("tags").Patch(nil)
	}
	opts := make([]formkit.Option, 0, len(tags))
	for _, t := range tags {
		opts = append(opts, formkit.Option{Value: t.Name, Label: fmt.Sprintf("%s (%d)", t.Name, t.Count)})
	}
	return multiChooser(call, "tags", opts, formkit.Success("pick tags (%d shown)", len(tags)))
}

// Search is the Find button on the templateQuery field. It reads the keyword from
// that control and rebuilds the templateIds field as a multi-select of matches.
func Search(r sdkv1.Request) any {
	call := rawCall(r.Data)
	query := firstNonEmpty(
		strVal(call["templateQuery"]),
		strVal(call["value"]),
		strVal(call["query"]),
	)
	if query == "" {
		return formkit.Info("type a keyword, then press Find").About("templateIds").Patch(nil)
	}

	sc := scannerFor(metaSettings(r.Data))
	defer sc.Close()

	matches, err := sc.Search(ctxOf(), query, 100)
	if err != nil {
		return formkit.Failure("search failed: %s", err).About("templateIds").Patch(nil)
	}
	if len(matches) == 0 {
		return formkit.Warning("no templates match %q", query).About("templateIds").Patch(nil)
	}
	opts := make([]formkit.Option, 0, len(matches))
	for _, m := range matches {
		label := m.ID
		if m.Severity != "" {
			label = fmt.Sprintf("%s  [%s]", m.ID, m.Severity)
		}
		opts = append(opts, formkit.Option{Value: m.ID, Label: label})
	}
	return multiChooser(call, "templateIds", opts, formkit.Success("%d match %q — tick the ones to run", len(matches), query))
}

func strVal(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

var _ = []func(sdkv1.Request) any{Profiles, Tags, Search}
var _ = nuclei.TagCount{}
