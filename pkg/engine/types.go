package engine

// Task represents a single request to be sent by a worker.
type Task struct {
	URL            string
	Method         string
	PostData       string
	Headers        map[string]string
	Payload        string
	InjectionPoint string
}

// Finding represents a detected vulnerability.
type Finding struct {
	Task      Task
	MatchInfo string
}
