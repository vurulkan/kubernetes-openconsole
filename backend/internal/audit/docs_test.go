package audit

import (
	"testing"

	"k8s-dashboard/backend/internal/models"
)

func TestAuditIsDocumented(t *testing.T) {
	for _, v := range Verbs {
		if VerbDocs[v] == "" {
			t.Errorf("VerbDocs[%q] missing", v)
		}
	}
	for _, o := range Outcomes {
		if OutcomeDocs[o] == "" {
			t.Errorf("OutcomeDocs[%q] missing", o)
		}
	}
	for k := range DetailKeys {
		if DetailDocs[k] == "" {
			t.Errorf("DetailDocs[%q] missing", k)
		}
	}
	if len(VerbDocs) != len(Verbs) || len(OutcomeDocs) != len(Outcomes) || len(DetailDocs) != len(DetailKeys) {
		t.Error("a *Docs map has an entry the registry doesn't")
	}
	// Every field of the console line is in FieldDocs, in the same order.
	e := models.AuditLog{Action: "a.b", Verb: "b", Outcome: "o", Reason: "r", User: "u", AuthSource: "s",
		Cluster: "c", ClusterID: 1, Namespace: "n", ResourceType: "a", ResourceName: "x", RequestID: "q",
		SourceIP: "i", UserAgent: "g", APIKeyID: 1, APIKeyName: "k"}
	attrs := consoleAttrs(e)
	if len(attrs) != len(FieldDocs) {
		t.Fatalf("console line has %d fields, FieldDocs %d", len(attrs), len(FieldDocs))
	}
	for i, a := range attrs {
		if a.Key != FieldDocs[i].Key || FieldDocs[i].Description == "" {
			t.Errorf("FieldDocs[%d] = %q, console field %q", i, FieldDocs[i].Key, a.Key)
		}
	}
}
