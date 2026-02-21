package engine

import (
	"net/url"
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

		var tasksList []Task
		for task := range tasks {
			tasksList = append(tasksList, task)
		}

		foundFile := false
		for _, task := range tasksList {
			if task.InjectionPoint == "URL_file" {
				foundFile = true
				if !strings.Contains(task.URL, "file="+payloads[0]) {
					t.Errorf("Expected URL to contain injected payload for file, got %s", task.URL)
				}
				if !strings.Contains(task.URL, "other=keep") {
					t.Errorf("Expected URL to keep other params, got %s", task.URL)
				}
			}
		}

		if !foundFile {
			t.Errorf("Expected a task injecting into 'file' parameter")
		}
	})

	// Test case 3: POST data injection
	t.Run("PostDataInjection", func(t *testing.T) {
		tasks := make(chan Task, 10)
		targetURL := "http://test.com/api"
		postData := "p1=val1&p2=val2"
		escapedPayload := url.QueryEscape(payloads[0])
		go func() {
			GenerateTasks(targetURL, payloads, postData, "POST", "", nil, false, tasks)
			close(tasks)
		}()

		// Expect 2 tasks, one for each parameter
		var tasksList []Task
		tasksList = append(tasksList, <-tasks)
		tasksList = append(tasksList, <-tasks)

		foundP1 := false
		foundP2 := false
		for _, t := range tasksList {
			if strings.Contains(t.PostData, "p1="+escapedPayload) && t.InjectionPoint == "POST_p1" {
				foundP1 = true
			}
			if strings.Contains(t.PostData, "p2="+escapedPayload) && t.InjectionPoint == "POST_p2" {
				foundP2 = true
			}
		}

		if !foundP1 {
			t.Errorf("Expected a task injecting into p1")
		}
		if !foundP2 {
			t.Errorf("Expected a task injecting into p2")
		}
	})
}
