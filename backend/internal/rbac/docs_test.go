package rbac

import "testing"

func TestCatalogIsDocumented(t *testing.T) {
	inCatalog := map[string]bool{}
	for _, c := range Catalog {
		if ResourceDocs[c.Resource] == "" {
			t.Errorf("ResourceDocs[%q] missing", c.Resource)
		}
		for _, a := range c.Actions {
			inCatalog[c.Resource+":"+a] = true
			if ActionDoc(c.Resource, a) == "" {
				t.Errorf("%s:%s has no description: add it to ActionDocs", c.Resource, a)
			}
		}
	}
	for k := range ActionDocs {
		if !inCatalog[k] {
			t.Errorf("ActionDocs[%q] is not in the Catalog", k)
		}
	}
}
