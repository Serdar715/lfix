package signatures

// Category defines the type of file or technology a signature belongs to.
type Category string

const (
	CategoryPasswd    Category = "passwd"
	CategoryShadow    Category = "shadow"
	CategoryBootIni   Category = "boot.ini"
	CategoryWinIni    Category = "win.ini"
	CategorySystemIni Category = "system.ini"
	CategoryIISConfig Category = "iis_config"
	CategoryPHPError  Category = "php_error"
	CategoryJava      Category = "java_web"
	CategoryGeneric   Category = "generic"
)

// Signature holds the pattern to search for, its category, and a confidence score (1-10).
// A score of 10 means the pattern is virtually impossible to appear legitimately in a web response.
// A score of 1-4 means the pattern is very common and should only contribute to a combined verdict.
type Signature struct {
	Pattern    string
	Category   Category
	Confidence int
}

// AllSignatures contains all detection patterns ordered by category and confidence.
// False-positive risk notes are documented inline.
var AllSignatures = []Signature{
	// -------------------------------------------------------------------------
	// LINUX /etc/passwd — Extremely high confidence: these strings appear
	// verbatim in the passwd file and are virtually absent from normal responses.
	// -------------------------------------------------------------------------
	{Pattern: "root:x:0:0:", Category: CategoryPasswd, Confidence: 10},
	{Pattern: "daemon:x:1:1:", Category: CategoryPasswd, Confidence: 9},
	{Pattern: "www-data:x:33:33:", Category: CategoryPasswd, Confidence: 9},
	{Pattern: "nobody:x:65534:", Category: CategoryPasswd, Confidence: 9},

	// -------------------------------------------------------------------------
	// LINUX /etc/shadow — Hash prefixes that only appear inside shadow files.
	// -------------------------------------------------------------------------
	{Pattern: "root:$6$", Category: CategoryShadow, Confidence: 10},
	{Pattern: "root:$5$", Category: CategoryShadow, Confidence: 10},
	{Pattern: "root:$1$", Category: CategoryShadow, Confidence: 10},
	{Pattern: "root:!:", Category: CategoryShadow, Confidence: 9},
	{Pattern: "root:*:", Category: CategoryShadow, Confidence: 9},

	// -------------------------------------------------------------------------
	// LINUX /proc/self/environ — Only accessible via LFI on Linux.
	// PATH= and HTTP_USER_AGENT= are environment variable exports that never
	// appear in normal HTTP responses.
	// -------------------------------------------------------------------------
	{Pattern: "HTTP_USER_AGENT=", Category: CategoryGeneric, Confidence: 10},
	{Pattern: "PATH=/usr/local/bin", Category: CategoryGeneric, Confidence: 8},

	// -------------------------------------------------------------------------
	// LINUX Error Logs — Apache/Nginx error log format.
	// FP risk: low — this exact format is rare outside log files.
	// -------------------------------------------------------------------------
	{Pattern: "[error] [client ", Category: CategoryGeneric, Confidence: 8},

	// -------------------------------------------------------------------------
	// WINDOWS boot.ini — Only present on older Windows systems.
	// "multi(0)disk(0)rdisk(0)" is a highly specific Windows disk descriptor.
	// -------------------------------------------------------------------------
	{Pattern: "multi(0)disk(0)rdisk(0)partition", Category: CategoryBootIni, Confidence: 10},
	{Pattern: "[boot loader]", Category: CategoryBootIni, Confidence: 8},

	// -------------------------------------------------------------------------
	// WINDOWS win.ini — The comment line is specific to win.ini structure.
	// FP note: lowered from 8 to 6 — this comment could theoretically appear in
	// documentation or config dumps on legitimate pages.
	// -------------------------------------------------------------------------
	{Pattern: "; for 16-bit app support", Category: CategoryWinIni, Confidence: 6},

	// -------------------------------------------------------------------------
	// WINDOWS system.ini — More specific patterns only.
	// "[extensions]" and "[drivers]" are too generic (can appear in any INI-like
	// content) so they are excluded. Only "wave=mmdrv.dll" is specific enough.
	// -------------------------------------------------------------------------
	{Pattern: "wave=mmdrv.dll", Category: CategorySystemIni, Confidence: 8},

	// -------------------------------------------------------------------------
	// IIS web.config — Microsoft-specific XML namespaces and tags.
	// "<configuration>" alone is too generic (any XML can contain it).
	// "<system.webServer>" and "<connectionStrings>" are IIS-specific.
	// -------------------------------------------------------------------------
	{Pattern: "<system.webServer>", Category: CategoryIISConfig, Confidence: 9},
	{Pattern: "<connectionStrings>", Category: CategoryIISConfig, Confidence: 10},
	// Low confidence for generic XML tag — only contributes to combined score.
	{Pattern: "<configuration xmlns", Category: CategoryIISConfig, Confidence: 4},

	// -------------------------------------------------------------------------
	// PHP Error Messages — PHP include/require failure strings are definitive
	// indicators of an LFI attempt that partially succeeded (path disclosure).
	// -------------------------------------------------------------------------
	{Pattern: "Warning: include(", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "Warning: require(", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "Warning: include_once(", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "Warning: require_once(", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "failed to open stream: No such file", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "Failed opening required", Category: CategoryPHPError, Confidence: 10},

	// -------------------------------------------------------------------------
	// JAVA / Tomcat — web.xml tags and FileNotFoundException are Java-specific.
	// -------------------------------------------------------------------------
	{Pattern: "<servlet-class>", Category: CategoryJava, Confidence: 8},
	{Pattern: "<servlet-mapping>", Category: CategoryJava, Confidence: 8},
	{Pattern: "java.io.FileNotFoundException:", Category: CategoryJava, Confidence: 9},
}
