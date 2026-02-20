package engine

import (
	"strings"
	"testing"
)

func TestGenerateTasks(t *testing.T) {
	payloads := []string{"../../etc/passwd"}

	// Test case 1: FUZZ mode in URL
	t.Run("FuzzModeURL", func(t *testing.T) {
		tasks := make(chan Task, 10)
		targetURL := "http://test.com/page?file=FUZZ"
		go func() {
			GenerateTasks(targetURL, payloads, "", "GET", "", nil, false, tasks)
			close(tasks)
		}()

		task := <-tasks
		if !strings.Contains(task.URL, payloads[0]) {
			t.Errorf("Expected URL to contain payload, got %s", task.URL)
		}
		if task.InjectionPoint != "CUSTOM_FUZZ" {
			t.Errorf("Expected injection point to be CUSTOM_FUZZ, got %s", task.InjectionPoint)
		}
	})

	// Test case 2: Automatic discovery in URL query
	t.Run("AutoDiscoveryURL", func(t *testing.T) {
		tasks := make(chan Task, 10)
		targetURL := "http://test.com/page?file=test&other=keep"
		go func() {
			GenerateTasks(targetURL, payloads, "", "GET", "", nil, false, tasks)
			close(tasks)
		}()

		task := <-tasks
		if !strings.Contains(task.URL, "file="+payloads[0]) {
			t.Errorf("Expected URL to contain injected payload, got %s", task.URL)
		}
		if !strings.Contains(task.URL, "other=keep") {
			t.Errorf("Expected URL to keep other params, got %s", task.URL)
		}
		if task.InjectionPoint != "URL_file" {
			t.Errorf("Expected injection point to be URL_file, got %s", task.InjectionPoint)
		}
	})

	// Test case 3: POST data injection
	t.Run("PostDataInjection", func(t *testing.T) {
		tasks := make(chan Task, 10)
		targetURL := "http://test.com/api"
		postData := "p1=val1&p2=val2"
		go func() {
			GenerateTasks(targetURL, payloads, postData, "POST", "", nil, false, tasks)
			close(tasks)
		}()

		// Expect 2 tasks, one for each parameter
		task1 := <-tasks
		task2 := <-tasks

		if !((strings.Contains(task1.PostData, "p1="+payloads[0]) && task1.InjectionPoint == "POST_p1") ||
			(strings.Contains(task2.PostData, "p1="+payloads[0]) && task2.InjectionPoint == "POST_p1")) {
			t.Errorf("Expected a task injecting into p1")
		}
		if !((strings.Contains(task1.PostData, "p2="+payloads[0]) && task1.InjectionPoint == "POST_p2") ||
			(strings.Contains(task2.PostData, "p2="+payloads[0]) && task2.InjectionPoint == "POST_p2")) {
			t.Errorf("Expected a task injecting into p2")
		}
	})
}
