package main

import (
	"fmt"
	"strings"
	"unicode"

	"k8s-dashboard/backend/internal/rbac"
)

// t returns the text of the page in lang. Turkish comes from trText, keyed by
// the English text; a missing entry stops docgen, so a new sentence can't ship
// untranslated. Trailing blank lines are kept as they are.
func t(lang, en string) string {
	if lang == "en" {
		return en
	}
	key := strings.TrimRight(en, "\n")
	tr, ok := trText[key]
	if !ok {
		fail(fmt.Errorf("no Turkish text for %q: add it to trText in cmd/docgen/tr.go", key))
	}
	return tr + en[len(key):]
}

// heading writes a "## " heading; in Turkish it carries the English anchor.
func heading(b *strings.Builder, lang, en string) { headingAs(b, lang, t(lang, en), en) }

func headingAs(b *strings.Builder, lang, text, en string) {
	if lang == "en" {
		fmt.Fprintf(b, "## %s\n\n", text)
		return
	}
	fmt.Fprintf(b, "## %s {#%s}\n\n", text, slug(en))
}

// slug is the anchor Docusaurus (github-slugger) makes from a heading.
func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

func init() {
	// Kubernetes kinds stay as they are.
	for _, kind := range rbac.ResourceDocs {
		if _, ok := trText[kind]; !ok {
			trText[kind] = kind
		}
	}
}

var trText = map[string]string{
	"descriptionsInEnglish": ":::note\n\nBaşlıklar ve tablolar Türkçe; açıklamalar koddan üretildiği için İngilizce.\n\n:::",

	// Titles and descriptions
	"Environment variables": "Ortam değişkenleri",
	"Every environment variable the server reads, with its default.": "Sunucunun okuduğu her ortam değişkeni ve varsayılanı.",
	"Application permissions": "Uygulama izinleri",
	"Every resource and action a role can grant, what it opens and its endpoints.": "Bir rolün verebileceği her kaynak ve aksiyon: neyi açtığı ve hangi uçları kullandığı.",
	"Audit events": "Denetim olayları",
	"Every audit action, its outcomes, fields and details, with their ECS names.": "Her denetim aksiyonu; sonuçları, alanları ve ayrıntıları, ECS adlarıyla.",
	"Metrics":                       "Metrikler",
	"Every series on GET /metrics.": "GET /metrics'teki her seri.",
	"Kubernetes permissions":        "Kubernetes izinleri",
	"What OpenConsole's ClusterRole grants in each cluster, rule by rule.": "OpenConsole'un ClusterRole'ünün her cluster'da verdiği yetkiler, kural kural.",
	"Keyboard shortcuts":                  "Klavye kısayolları",
	"Every keyboard shortcut of the app.": "Uygulamanın bütün klavye kısayolları.",

	// Table headers and small words
	"Variable":          "Değişken",
	"Default":           "Varsayılan",
	"Description":       "Açıklama",
	"`false` turns off": "`false` neyi kapatır",
	"Permission":        "İzin",
	"Opens":             "Ne açar",
	"Safe read-only":    "Güvenli salt okuma",
	"Endpoints":         "Uçlar",
	"Metric":            "Metrik",
	"Type":              "Tür",
	"Labels":            "Label'lar",
	"Meaning":           "Anlamı",
	"API group":         "API grubu",
	"Resources":         "Kaynaklar",
	"Verbs":             "İşlem türleri",
	"Used for":          "Ne için",
	"Keys":              "Tuşlar",
	"Does":              "Ne yapar",
	"Field":             "Alan",
	"ECS":               "ECS",
	"Action":            "Aksiyon",
	"Actions":           "Aksiyonlar",
	"Outcomes":          "Sonuçlar",
	"Verb":              "İşlem türü",
	"Outcome":           "Sonuç",
	"Key":               "Anahtar",
	"Fields":            "Alanlar",
	"Details":           "Ayrıntılar",
	"none":              "yok",
	"; image: ":         "; imaj: ",
	"yes":               "evet",
	" (only ":           " (yalnız ",
	" then ":            " sonra ",
	" or ":              " ya da ",
	"**Not granted** (commented out in the file). ": "**Verilmez** (dosyada yorum satırı). ",

	// Environment variables
	"Core":                    "Temel",
	"Logging":                 "Loglama",
	"Tracing (OpenTelemetry)": "Tracing (OpenTelemetry)",
	"Security and limits":     "Güvenlik ve limitler",
	"Sign-in":                 "Giriş",
	"Session recording":       "Oturum kaydı",
	"Feature flags":           "Özellik bayrakları",
	"Every variable the server reads. Set them on the container; `deploy/deployment.yaml` lists the common ones. " +
		"**Default** is what the server uses when the variable is unset; the image and `deploy/deployment.yaml` set a few themselves.": "Sunucunun okuduğu bütün değişkenler. Bunları container'a verin; sık kullanılanlar `deploy/deployment.yaml` içinde. " +
		"**Varsayılan**, değişken tanımlı değilken sunucunun kullandığı değerdir; birkaçını imaj ve `deploy/deployment.yaml` kendisi ayarlar.",
	"A value that doesn't parse, or is below the minimum, falls back to the default.": "Okunamayan ya da alt sınırın altında kalan bir değerin yerine varsayılan kullanılır.",
	"Recording is configured in **Admin → Recordings → Recording settings** and stored in the database. " +
		"These variables only seed those settings on the very first start (useful for scripted installs), except " +
		"`SESSION_RECORDING_DIR`, which is read on every start.": "Kayıt, **Yönetim → Kayıtlar → Kayıt ayarları** ekranında yapılandırılır ve veritabanında tutulur. " +
		"Bu değişkenler o ayarları yalnız ilk açılışta doldurur (betikle yapılan kurulumlarda işe yarar). " +
		"İstisna `SESSION_RECORDING_DIR`: her açılışta okunur.",
	"Switch a capability off **for everyone, admins included**, whatever the roles grant: `FEATURE_<NAME>=false` " +
		"(or `0`, `no`). Anything else, or unset, leaves it on. A disabled feature disappears from the UI, its endpoints " +
		"answer 403 `feature_disabled` and the attempt is audited as `denied`. `GET /api/features` shows the current state; " +
		"the startup log lists what is off.": "Bir yeteneği, roller ne verirse versin **adminler dahil herkes için** kapatır: `FEATURE_<NAME>=false` " +
		"(ya da `0`, `no`). Başka bir değer ya da tanımsız bırakmak açık tutar. Kapalı bir özellik arayüzden kaybolur, uçları " +
		"403 `feature_disabled` döner ve deneme `denied` olarak audit'e yazılır. `GET /api/features` güncel durumu gösterir; " +
		"açılış logu kapalı olanları listeler.",

	// Application permissions
	"Granted per role, per namespace, per cluster (or all clusters) under **Admin → Roles**. Admins hold all of them. " +
		"A user's permission is checked on every request, in the namespace of the request.\n\n" +
		"**Safe read-only** marks the grants of the API access mode of the same name and of the API key template: " +
		"`list`, `get` and `logs`, except on ConfigMaps and Secrets, whose data can hold credentials.\n\n" +
		"**Endpoints** come from the API description (`/api/openapi.json`); an endpoint that needs two permissions is " +
		"listed under both. The Kubernetes rights behind each one are on [Kubernetes permissions](kubernetes-permissions.md).": "**Yönetim → Roller** ekranında rol, namespace ve cluster başına (ya da tüm cluster'lar için) verilir. Adminlerde hepsi vardır. " +
		"Kullanıcının izni her istekte, isteğin namespace'inde kontrol edilir.\n\n" +
		"**Güvenli salt okuma**, aynı adlı API erişim modunun ve API anahtarı şablonunun verdiği izinleri işaretler: " +
		"`list`, `get` ve `logs`; ConfigMap ve Secret hariç, çünkü verileri kimlik bilgisi taşıyabilir.\n\n" +
		"**Uçlar** API tanımından (`/api/openapi.json`) gelir; iki izin isteyen bir uç ikisinin altında da yer alır. " +
		"Her birinin arkasındaki Kubernetes yetkileri [Kubernetes izinleri](kubernetes-permissions.md) sayfasında.",

	// Metrics
	"`GET /metrics` serves these in the Prometheus text format, without sign-in: scrape it from inside the " +
		"cluster and don't route it through your Ingress. Counters start at 0 when the pod starts.": "`GET /metrics` bunları Prometheus metin formatında, giriş istemeden sunar: cluster'ın içinden scrape edin, " +
		"Ingress'inizden geçirmeyin. Sayaçlar pod açılınca 0'dan başlar.",

	// Kubernetes permissions
	"OpenConsole talks to each cluster with the identity you give it under **Admin → Clusters**, normally the " +
		"ServiceAccount of `deploy/rbac.yaml`. That ClusterRole is the ceiling: a user can never do more in a cluster than " +
		"it allows, whatever their OpenConsole roles grant. Remove a rule if you will never grant the matching permission. " +
		"For a console that can only look, apply `deploy/rbac-readonly.yaml` instead (same object names, so applying one " +
		"replaces the other).": "OpenConsole her cluster'a **Yönetim → Cluster'lar** ekranında verdiğiniz kimlikle bağlanır; bu normalde " +
		"`deploy/rbac.yaml` dosyasındaki ServiceAccount'tur. O ClusterRole tavandır: OpenConsole rolleri ne verirse versin, " +
		"kullanıcı bir cluster'da onun izin verdiğinden fazlasını yapamaz. Karşılık gelen izni hiç vermeyecekseniz kuralı silin. " +
		"Yalnız bakabilen bir konsol için onun yerine `deploy/rbac-readonly.yaml` uygulayın (nesne adları aynı, biri diğerinin " +
		"yerine geçer).",
	"Full (`deploy/rbac.yaml`)":               "Tam (`deploy/rbac.yaml`)",
	"Read only (`deploy/rbac-readonly.yaml`)": "Salt okuma (`deploy/rbac-readonly.yaml`)",

	// Keyboard shortcuts
	"The same list as **?** in the app. \"`g` then `o`\" means: press `g`, then `o` within a second; \"or\" " +
		"means either key works. On a Turkish Q keyboard the shortcuts follow the key's position, so `ğ` `ü` `.` work as " +
		"`[` `]` `/`. Shortcuts don't fire while you type in a text field.": "Uygulamadaki **?** listesinin aynısı. \"`g` sonra `o`\": `g`'ye, bir saniye içinde de `o`'ya basın; \"ya da\": " +
		"iki tuştan biri yeter. Türkçe Q klavyede kısayollar tuşun konumuna göre çalışır, yani `ğ` `ü` `.` tuşları " +
		"`[` `]` `/` gibi davranır. Bir metin alanına yazarken kısayollar çalışmaz.",

	// Audit events
	"Every audited action is one event. It is stored in the database (**Admin → Audit Logs**, CSV export) and, " +
		"with `LOG_INCLUDE_AUDIT=true` (the default), written to stdout as one line, so the same fields can be filtered in " +
		"the UI and in your log platform. The **ECS** names apply with `LOG_FORMAT=ecs`; `json` uses the plain names.\n\n" +
		"Reads are audited too (`deployment.list`, `pod.get`, `pod.logs`), refused ones included. The lists the UI reloads " +
		"on its own are not (they send `X-OpenConsole-Refresh: auto`); the HTTP request log still has every request. " +
		"With an API key that header is ignored: every read is audited.": "Audit'e yazılan her aksiyon bir olaydır. Veritabanında tutulur (**Yönetim → Denetim Logları**, CSV dışa aktarma) ve " +
		"`LOG_INCLUDE_AUDIT=true` ile (varsayılan) stdout'a tek satır olarak yazılır; böylece aynı alanlar hem arayüzde hem log " +
		"platformunuzda filtrelenebilir. **ECS** adları `LOG_FORMAT=ecs` ile geçerlidir; `json` düz adları kullanır.\n\n" +
		"Okumalar da audit'e yazılır (`deployment.list`, `pod.get`, `pod.logs`), reddedilenler dahil. Arayüzün kendi kendine " +
		"yenilediği listeler yazılmaz (`X-OpenConsole-Refresh: auto` gönderirler); HTTP istek logunda yine her istek vardır. " +
		"API anahtarıyla bu header yok sayılır: her okuma audit'e yazılır.",
	"The action is `<resource type>.<verb>`. Read from the handlers' code; an action shows every " +
		"outcome it can end with. `<resource>` stands for any Kubernetes resource type the check is made for (`pod`, " +
		"`deployment`, …).": "Aksiyon `<resource type>.<verb>` biçimindedir. Handler'ların kodundan okunur; her aksiyon, bitebileceği " +
		"bütün sonuçlarla listelenir. `<resource>`, kontrolün yapıldığı herhangi bir Kubernetes kaynak türünün yerine geçer " +
		"(`pod`, `deployment`, …).",
	"A fixed set of typed keys; each is its own field on the log line. They never hold a secret " +
		"value, a YAML body, a password or a token. **Type** is the Elasticsearch type in `deploy/elk`.": "Türü belli, sabit bir anahtar kümesi; her biri log satırında ayrı bir alandır. Hiçbir zaman secret değeri, YAML " +
		"gövdesi, parola ya da token taşımaz. **Tür**, `deploy/elk` içindeki Elasticsearch türüdür.",
}
