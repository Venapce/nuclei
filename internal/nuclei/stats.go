package nuclei

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// readStatsTags reads the tag counts from the catalog's TEMPLATES-STATS.json,
// which the nuclei-templates repo ships at its root. Returns nil (not an error)
// when the file is absent — the tag browser is a convenience, not a dependency.
func readStatsTags(templatesDir string, limit int) ([]TagCount, error) {
	if templatesDir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(templatesDir, "TEMPLATES-STATS.json"))
	if err != nil {
		return nil, nil
	}
	var stats struct {
		Tags []TagCount `json:"tags"`
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, nil
	}
	if limit > 0 && len(stats.Tags) > limit {
		stats.Tags = stats.Tags[:limit]
	}
	return stats.Tags, nil
}
