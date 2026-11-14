package rbac

// ResourceDocs and ActionDocs describe the Catalog for the docs site's
// Permissions page (cmd/docgen); docs_test.go keeps them complete. Endpoints
// per permission come from the OpenAPI description, not from here.
var ResourceDocs = map[string]string{
	"pods":         "Pods",
	"deployments":  "Deployments",
	"daemonsets":   "DaemonSets",
	"statefulsets": "StatefulSets",
	"hpas":         "HorizontalPodAutoscalers",
	"services":     "Services",
	"configmaps":   "ConfigMaps",
	"secrets":      "Secrets",
	"ingresses":    "Ingresses",
	"cronjobs":     "CronJobs",
	"jobs":         "Jobs",
}

// ActionDocs: "<resource>:<action>" → what it opens. Plain list / get / edit
// of most resources share genericActionDocs.
var ActionDocs = map[string]string{
	"pods:get":            "The pod drawer: status, containers, events, restart history, CPU / memory; the YAML view.",
	"pods:logs":           "Pod logs: live, previous container, download, the REST log snapshot. With `deployments:get` / `jobs:get`, the logs of every pod of a Deployment or Job.",
	"pods:exec":           "A shell in a container, and one command over the API. Every session is audited; sessions opened with an API key are always recorded.",
	"deployments:get":     "The Deployment drawer (revisions read only, pods, usage); the YAML view.",
	"deployments:restart": "Rolling restart: patches the pod template's `restartedAt` annotation.",
	"deployments:scale":   "Change the replica count (0 to `MAX_REPLICAS`).",
	"statefulsets:get":    "The StatefulSet drawer and the YAML view.",
	"statefulsets:scale":  "Change the replica count (0 to `MAX_REPLICAS`).",
	"daemonsets:get":      "The DaemonSet drawer and the YAML view.",
	"secrets:list":        "The Secrets tab: names, types and key names. Never the values.",
	"secrets:get":         "One Secret's metadata, key names and value sizes. Never the values.",
	"secrets:reveal":      "Show one value of a Secret per request. Each reveal is audited with the key name.",
	"secrets:edit":        "The Secret YAML editor, which shows every value, and apply. Opening it is audited as `secret.view_yaml`.",
	"cronjobs:trigger":    "Fake permission: this branch checks that CI fails when docgen wasn't run.",
	"configmaps:get":      "One ConfigMap with its data; the YAML view.",
}

var genericActionDocs = map[string]string{
	"list": "The resource's Dashboard tab and its list endpoint.",
	"get":  "One object: its detail and the YAML view.",
	"edit": "Edit and apply the YAML, with a server-side dry run first.",
}

// ActionDoc returns the description of resource:action.
func ActionDoc(resource, action string) string {
	if d, ok := ActionDocs[resource+":"+action]; ok {
		return d
	}
	return genericActionDocs[action]
}
