package scanner

// The popular plugin/theme slug lists below are STATIC SEEDS for aggressive
// enumeration: well-known WordPress components that are not necessarily in
// the vulnerability database (whose top-slug list funds the normal
// enumeration). They are curated by hand and may drift from the current
// WordPress.org marketplace; they exist to widen coverage, and PopularSlugs
// (CLI default true) gates whether buildJobs appends them. Ordering is the
// deterministic append order — no sorting happens here.

// popularPlugins is a seed list of ~100 widely-installed WordPress plugin
// slugs appended to aggressive enumeration after the DB top-slug list.
var popularPlugins = []string{
	"contact-form-7", "akismet", "wordpress-seo", "elementor",
	"wpforms-lite", "jetpack", "woocommerce", "classic-editor",
	"all-in-one-seo-pack", "google-analytics-for-wordpress",
	"wordfence", "really-simple-ssl", "wp-super-cache", "updraftplus",
	"duplicate-post", "lite-speed-cache", "w3-total-cache", "autoptimize",
	"wp-mail-smtp", "smtp-mailer", "wp-rocket", "regenerate-thumbnails",
	"limit-login-attempts-reloaded", "loginizer", "redirection",
	"wordpress-importer", "xml-sitemap-feed", "better-wp-security",
	"i-theme-security", "all-in-one-wp-migration", "easy-digital-downloads",
	"wpforms", "formidable", "ninja-forms", "gravity-forms", "contact-form-7-dynamic-text-extension",
	"woocommerce-gateway-stripe", "woocommerce-paypal-payments",
	"siteorigin-panels", "elementor-pro", "essential-addons-for-elementor-lite",
	"shortcodes-ultimate", "maxbuttons", "tablepress", "wp-pagenavi",
	"breadcrumb-navxt", "wordfence-login-security", "disable-comments",
	"antispam-bee", "clean-and-simple-contact-form", "cookie-notice",
	"cookie-law-info", "complianz-gdpr", "gdpr-cookie-compliance",
	"tinymce-advanced", "code-snippets", "insert-headers-and-footers",
	"duracelltomi-google-tag-manager", "monsterinsights", "ga-google-analytics",
	"wp-optimize", "imagify", "smush", "ewww-image-optimizer",
	"shortpixel-image-optimiser", "webp-converter-for-media",
	"advanced-custom-fields", "acf-content-analysis-for-yoast-seo",
	"custom-post-type-ui", "toolset-types", "pods", "wpml",
	"polylang", "translatepress-multilingual", "loco-translate",
	"mailchimp-for-wp", "wpforms-mailchimp", "newsletter", "mailpoet",
	"fluentform", "forminator", "buddypress", "bbpress",
	"ultimate-member", "user-role-editor", "members", "wp-members",
	"wp-user-avatar", "simple-membership", "paid-memberships-pro",
	"download-manager", "simple-download-monitor", "media-library-assistant",
	"nextgen-gallery", "envira-gallery-lite", "modula-best-grid-gallery",
	"slider-revolution", "smart-slider-3", "meta-box", "yoast-test-helper",
}

// popularThemes is a seed list of ~30 widely-installed WordPress theme
// slugs appended to aggressive enumeration after the DB top-slug list.
var popularThemes = []string{
	"twentytwentyfive", "twentytwentyfour", "twentytwentythree",
	"twentytwentytwo", "twentytwentyone", "twentytwenty",
	"generatepress", "astra", "hello-elementor", "oceanwp",
	"flatsome", "storefront", "kadence", "neve",
	"zakra", "blocksy", "spacious", "colormag",
	"hestia", "shapely", "popularfx", "hestia-pro",
	"customify", "hestia-child", "onepress", "consulting",
	"avada", "bridge", "enfold", "divi",
}
