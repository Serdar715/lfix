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

// Signature holds the pattern to search for, its category, and a confidence score.
type Signature struct {
	Pattern    string
	Category   Category
	Confidence int
}

// AllSignatures contains the list of all signatures used for detection.
// Confidence Score (1-10): 10 is highest confidence.
var AllSignatures = []Signature{
	// --- LINUX /etc/passwd (High Confidence) ---
	{Pattern: "root:x:0:0:", Category: CategoryPasswd, Confidence: 10},
	{Pattern: "daemon:x:1:1:", Category: CategoryPasswd, Confidence: 8},
	{Pattern: "www-data:x:33:33:", Category: CategoryPasswd, Confidence: 8},
	{Pattern: "nobody:x:65534:", Category: CategoryPasswd, Confidence: 8},

	// --- LINUX /etc/shadow (High Confidence) ---
	{Pattern: "root:$6$", Category: CategoryShadow, Confidence: 10},
	{Pattern: "root:$5$", Category: CategoryShadow, Confidence: 10},
	{Pattern: "root:$1$", Category: CategoryShadow, Confidence: 10},
	{Pattern: "root:!:", Category: CategoryShadow, Confidence: 9},
	{Pattern: "root:*:", Category: CategoryShadow, Confidence: 9},

	// --- WINDOWS boot.ini (Medium-High Confidence) ---
	{Pattern: "[boot loader]", Category: CategoryBootIni, Confidence: 7},
	{Pattern: "multi(0)disk(0)rdisk(0)partition", Category: CategoryBootIni, Confidence: 8},

	// --- WINDOWS win.ini (Low-Medium Confidence) ---
	{Pattern: "for 16-bit app support", Category: CategoryWinIni, Confidence: 5},

	// --- WINDOWS system.ini (Low Confidence) ---
	{Pattern: "[drivers]", Category: CategorySystemIni, Confidence: 3},
	{Pattern: "[mci]", Category: CategorySystemIni, Confidence: 3},
	{Pattern: "wave=mmdrv.dll", Category: CategorySystemIni, Confidence: 4},

	// --- IIS web.config (High Confidence) ---
	{Pattern: "<configuration>", Category: CategoryIISConfig, Confidence: 7}, // Can be generic, but context matters
	{Pattern: "<system.webServer>", Category: CategoryIISConfig, Confidence: 8},
	{Pattern: "<connectionStrings>", Category: CategoryIISConfig, Confidence: 9},

	// --- PHP HATA MESAJLARI (Highest Confidence) ---
	{Pattern: "Warning: include(", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "Warning: require(", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "failed to open stream: No such file", Category: CategoryPHPError, Confidence: 10},
	{Pattern: "Failed opening required", Category: CategoryPHPError, Confidence: 10},

	// --- JAVA / TOMCAT (Medium Confidence) ---
	{Pattern: "<servlet-class>", Category: CategoryJava, Confidence: 7},
	{Pattern: "<servlet-mapping>", Category: CategoryJava, Confidence: 7},
}
