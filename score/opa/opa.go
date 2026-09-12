// Package opa provides OPA/Rego policy passthrough for kube-score.
// It loads all .rego files from a directory, evaluates each against every
// Kubernetes object in the parsed input, and merges deny[msg] decisions
// into the scorecard as additional findings.
//
// Policy files may include a header comment to override the default score weight:
//
//	# kube-score/weight: 1
//
// Valid weights match scorecard grade constants: 1 (critical), 5 (warning), 10 (ok).
// The default weight is 5 (warning).
package opa

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	oprego "github.com/open-policy-agent/opa/rego"
	"github.com/zegl/kube-score/config"
	ks "github.com/zegl/kube-score/domain"
	"github.com/zegl/kube-score/scorecard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const defaultWeight = scorecard.GradeWarning // 5

// policyFile holds a loaded .rego file and its parsed metadata.
type policyFile struct {
	filename string
	content  string
	pkgName  string
	weight   scorecard.Grade
}

// LoadAndApply reads all .rego files from dir, evaluates each policy against
// every Kubernetes object in allObjects, and adds deny[msg] findings to sc.
func LoadAndApply(sc scorecard.Scorecard, allObjects ks.AllTypes, dir string, cnf *config.RunConfiguration) error {
	policies, err := loadPolicies(dir)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	ctx := context.Background()
	return applyPolicies(ctx, sc, allObjects, policies, cnf)
}

// loadPolicies reads all .rego files from dir.
func loadPolicies(dir string) ([]policyFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("opa: cannot read policy directory %q: %w", dir, err)
	}
	var policies []policyFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("opa: cannot read policy %q: %w", fullPath, err)
		}
		content := string(data)
		policies = append(policies, policyFile{
			filename: e.Name(),
			content:  content,
			pkgName:  parsePackageName(content),
			weight:   parseWeight(content),
		})
	}
	return policies, nil
}

// parsePackageName extracts the Rego package declaration from file content.
// Returns "main" if no package declaration is found.
func parsePackageName(content string) string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "package ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return "main"
}

// parseWeight scans the header comment block for a kube-score/weight directive.
// Returns defaultWeight if the directive is absent or malformed.
func parseWeight(content string) scorecard.Grade {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Stop scanning at the first non-comment, non-empty line.
		if line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		const prefix = "# kube-score/weight:"
		if strings.HasPrefix(line, prefix) {
			raw := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			n, err := strconv.Atoi(raw)
			if err == nil && n > 0 {
				return scorecard.Grade(n)
			}
		}
	}
	return defaultWeight
}

// evalObject evaluates all policies against one Kubernetes object and returns
// the deny messages produced.
func evalObject(ctx context.Context, policies []policyFile, input interface{}) ([]policyDeny, error) {
	// Marshal to JSON then back to map[string]interface{} so OPA receives
	// plain Go types rather than typed Kubernetes structs.
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("opa: failed to marshal object: %w", err)
	}
	var inputMap map[string]interface{}
	if err := json.Unmarshal(raw, &inputMap); err != nil {
		return nil, fmt.Errorf("opa: failed to unmarshal object to map: %w", err)
	}

	var results []policyDeny
	for _, pol := range policies {
		query := fmt.Sprintf("data.%s.deny[x]", pol.pkgName)
		r := oprego.New(
			oprego.Query(query),
			oprego.Module(pol.filename, pol.content),
			oprego.Input(inputMap),
		)
		rs, err := r.Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("opa: policy %q evaluation failed: %w", pol.filename, err)
		}
		for _, result := range rs {
			if msg, ok := result.Bindings["x"].(string); ok && msg != "" {
				results = append(results, policyDeny{
					filename: pol.filename,
					message:  msg,
					weight:   pol.weight,
				})
			}
		}
	}
	return results, nil
}

// policyDeny holds a single deny message produced by a Rego policy.
type policyDeny struct {
	filename string
	message  string
	weight   scorecard.Grade
}

// podSpecerInput is a JSON-serializable view of a PodSpecer for Rego evaluation.
type podSpecerInput struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
}

// addFindings evaluates all policies against obj and adds deny findings to sc.
func addFindings(
	ctx context.Context,
	sc scorecard.Scorecard,
	typeMeta metav1.TypeMeta,
	objectMeta metav1.ObjectMeta,
	locationer ks.FileLocationer,
	policies []policyFile,
	input interface{},
	cnf *config.RunConfiguration,
) error {
	denies, err := evalObject(ctx, policies, input)
	if err != nil {
		return err
	}
	if len(denies) == 0 {
		return nil
	}
	o := sc.NewObject(typeMeta, objectMeta, cnf)
	for _, d := range denies {
		ruleID := "custom/" + d.filename + "/deny"
		ch := ks.Check{
			Name:       ruleID,
			ID:         ruleID,
			TargetType: typeMeta.Kind,
			Comment:    "Custom OPA/Rego policy: " + d.filename,
			Optional:   false,
		}
		ts := scorecard.TestScore{Grade: d.weight}
		ts.AddComment("", d.message, "Denied by Rego policy: "+d.filename)
		o.Add(ts, ch, locationer)
	}
	return nil
}

// applyPolicies evaluates policies against every object in allObjects.
func applyPolicies(
	ctx context.Context,
	sc scorecard.Scorecard,
	allObjects ks.AllTypes,
	policies []policyFile,
	cnf *config.RunConfiguration,
) error {
	// Pods
	for _, pod := range allObjects.Pods() {
		p := pod.Pod()
		if err := addFindings(ctx, sc, p.TypeMeta, p.ObjectMeta, pod, policies, p, cnf); err != nil {
			return err
		}
	}

	// Services
	for _, svc := range allObjects.Services() {
		s := svc.Service()
		if err := addFindings(ctx, sc, s.TypeMeta, s.ObjectMeta, svc, policies, s, cnf); err != nil {
			return err
		}
	}

	// StatefulSets (full typed object available)
	for _, ss := range allObjects.StatefulSets() {
		obj := ss.StatefulSet()
		if err := addFindings(ctx, sc, obj.TypeMeta, obj.ObjectMeta, ss, policies, obj, cnf); err != nil {
			return err
		}
	}

	// Deployments (full typed object available)
	for _, dep := range allObjects.Deployments() {
		obj := dep.Deployment()
		if err := addFindings(ctx, sc, obj.TypeMeta, obj.ObjectMeta, dep, policies, obj, cnf); err != nil {
			return err
		}
	}

	// NetworkPolicies
	for _, np := range allObjects.NetworkPolicies() {
		obj := np.NetworkPolicy()
		if err := addFindings(ctx, sc, obj.TypeMeta, obj.ObjectMeta, np, policies, obj, cnf); err != nil {
			return err
		}
	}

	// PodSpeccers covers Deployments (older API versions), StatefulSets (older API),
	// DaemonSets, Jobs, CronJobs, and others that have a pod template. We use a
	// synthetic input containing at least apiVersion, kind, and metadata because
	// the PodSpecer interface does not expose the full typed object.
	// To avoid evaluating modern Deployments and StatefulSets twice (they are also
	// returned by Deployments() and StatefulSets()), we skip them here.
	seen := make(map[string]bool)
	for _, dep := range allObjects.Deployments() {
		obj := dep.Deployment()
		seen[objectKey(obj.TypeMeta, obj.ObjectMeta)] = true
	}
	for _, ss := range allObjects.StatefulSets() {
		obj := ss.StatefulSet()
		seen[objectKey(obj.TypeMeta, obj.ObjectMeta)] = true
	}

	for _, ps := range allObjects.PodSpeccers() {
		tm := ps.GetTypeMeta()
		om := ps.GetObjectMeta()
		if seen[objectKey(tm, om)] {
			continue
		}
		input := podSpecerInput{
			APIVersion: tm.APIVersion,
			Kind:       tm.Kind,
			Metadata:   om,
		}
		if err := addFindings(ctx, sc, tm, om, ps, policies, input, cnf); err != nil {
			return err
		}
	}

	return nil
}

func objectKey(tm metav1.TypeMeta, om metav1.ObjectMeta) string {
	return tm.Kind + "/" + tm.APIVersion + "/" + om.Namespace + "/" + om.Name
}
