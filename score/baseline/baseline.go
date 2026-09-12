// Package baseline provides serialization and suppression of kube-score findings
// so that a known-good baseline of issues can be tracked and ignored on future
// scans. The baseline maps a resource identity to the list of check IDs that
// were failing at the time the baseline was captured.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/zegl/kube-score/scorecard"
)

// Baseline maps resource identity to a list of check IDs that are suppressed.
// Namespaced resources use "namespace/name"; cluster-scoped resources use "name".
type Baseline map[string][]string

// ResourceKey returns the baseline map key for a given namespace and name.
func ResourceKey(namespace, name string) string {
	if namespace != "" {
		return namespace + "/" + name
	}
	return name
}

// Save serializes non-OK findings from sc into a JSON baseline file at path.
// Only checks that produced a grade at or below GradeWarning are saved.
func Save(path string, sc *scorecard.Scorecard) error {
	b := make(Baseline)
	for _, obj := range *sc {
		key := ResourceKey(obj.ObjectMeta.Namespace, obj.ObjectMeta.Name)
		for _, check := range obj.Checks {
			if check.Skipped {
				continue
			}
			if check.Grade <= scorecard.GradeWarning {
				b[key] = append(b[key], check.Check.ID)
			}
		}
	}

	// Deduplicate and sort check IDs within each entry for stable output.
	for key := range b {
		ids := dedup(b[key])
		sort.Strings(ids)
		b[key] = ids
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: failed to marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("baseline: failed to write %q: %w", path, err)
	}
	return nil
}

// Load reads a baseline JSON file from path.
func Load(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: failed to read %q: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("baseline: failed to parse %q: %w", path, err)
	}
	return b, nil
}

// Suppress marks as skipped any check in sc whose combination of resource
// identity and check ID is present in b. It returns the total count of
// suppressed findings.
func Suppress(sc *scorecard.Scorecard, b Baseline) int {
	count := 0
	for _, obj := range *sc {
		key := ResourceKey(obj.ObjectMeta.Namespace, obj.ObjectMeta.Name)
		suppressed, ok := b[key]
		if !ok {
			continue
		}
		suppressSet := make(map[string]bool, len(suppressed))
		for _, id := range suppressed {
			suppressSet[id] = true
		}
		for i := range obj.Checks {
			if obj.Checks[i].Skipped {
				continue
			}
			if suppressSet[obj.Checks[i].Check.ID] {
				obj.Checks[i].Skipped = true
				obj.Checks[i].Comments = []scorecard.TestScoreComment{
					{Summary: fmt.Sprintf("Suppressed by baseline: %s", obj.Checks[i].Check.ID)},
				}
				count++
			}
		}
	}
	return count
}

// CheckStrict returns an error when the baseline references resource keys that
// are absent from sc. This catches baselines that have grown stale after
// resources are renamed or removed.
func CheckStrict(sc *scorecard.Scorecard, b Baseline, baselinePath string) error {
	present := make(map[string]bool, len(*sc))
	for _, obj := range *sc {
		present[ResourceKey(obj.ObjectMeta.Namespace, obj.ObjectMeta.Name)] = true
	}
	var missing []string
	for key := range b {
		if !present[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("--baseline-strict: baseline %q references resources not present in the input: %v", baselinePath, missing)
	}
	return nil
}

func dedup(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := ids[:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
