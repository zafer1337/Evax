package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/go-toast/toast"
	openai "github.com/sashabaranov/go-openai"
)

// LogEntry represents a single log entry fetched from Windows Event Viewer.
type LogEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Details   string `json:"details"`
}

// Anomaly represents an identified anomaly in the logs.
type Anomaly struct {
	LogID       string `json:"log_id"`
	Description string `json:"description"`
}

// fetchWindowsEventLogs fetches security logs from Windows Event Viewer using `wevtutil`.
func fetchWindowsEventLogs() ([]LogEntry, error) {
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/f:Text")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch logs: %w", err)
	}
	return parseWindowsLogs(string(output)), nil
}

// parseWindowsLogs parses the raw log data into a structured format.
func parseWindowsLogs(rawLogs string) []LogEntry {
	lines := strings.Split(rawLogs, "\n")
	var logs []LogEntry
	var current LogEntry
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Event ID:") {
			current = LogEntry{}
			current.ID = strings.TrimPrefix(line, "Event ID: ")
		} else if strings.HasPrefix(line, "Time Created:") {
			current.Timestamp = strings.TrimPrefix(line, "Time Created: ")
		} else if strings.HasPrefix(line, "Task:") {
			current.EventType = strings.TrimPrefix(line, "Task: ")
		} else if strings.HasPrefix(line, "Message:") {
			current.Details = strings.TrimPrefix(line, "Message: ")
			logs = append(logs, current)
		}
	}
	return logs
}

// analyzeLogs detects anomalies in the logs using rule-based logic.
func analyzeLogs(logs []LogEntry) []Anomaly {
	anomalies := []Anomaly{}
	for _, log := range logs {
		if isAnomalous(log) {
			anomalies = append(anomalies, Anomaly{
				LogID:       log.ID,
				Description: fmt.Sprintf("Potential anomaly detected in log with ID %s: %s", log.ID, log.Details),
			})
		}
	}
	return anomalies
}

// isAnomalous checks if a log entry is anomalous using embedded rules.
func isAnomalous(log LogEntry) bool {
	return strings.Contains(strings.ToLower(log.Details), "failed login") ||
		strings.Contains(strings.ToLower(log.Details), "account locked")
}

// escalateToOpenAI sends the anomaly description to OpenAI for further analysis.
func escalateToOpenAI(anomaly Anomaly) (string, error) {
	client := openai.NewClient("OPENAIKEY")
	ctx := context.Background()

	prompt := fmt.Sprintf("Provide a concise explanation for the following anomaly:\n%s", anomaly.Description)
	resp, err := client.CreateCompletion(ctx, openai.CompletionRequest{
		Model:     "text-davinci-003",
		Prompt:    prompt,
		MaxTokens: 50,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get response from OpenAI: %w", err)
	}

	return strings.TrimSpace(resp.Choices[0].Text), nil
}

// sendWindowsNotification sends a Windows notification with the provided message.
func sendWindowsNotification(title, message string) {
	notification := toast.Notification{
		AppID:   "Windows Security Audit",
		Title:   title,
		Message: message,
		Icon:    "", // Optional: Path to an icon file.
	}
	if err := notification.Push(); err != nil {
		log.Printf("Failed to send notification: %v", err)
	}
}

func main() {
	// Step 1: Fetch Windows Event Logs
	logs, err := fetchWindowsEventLogs()
	if err != nil {
		log.Fatalf("Error fetching logs: %v", err)
	}
	fmt.Printf("Fetched %d logs.\n", len(logs))

	// Step 2: Analyze logs for anomalies
	anomalies := analyzeLogs(logs)
	if len(anomalies) == 0 {
		message := "No anomalies detected. Your system is safe."
		fmt.Println(message)
		sendWindowsNotification("Security Audit", message)
		return
	}

	// Step 3: Handle anomalies
	for _, anomaly := range anomalies {
		fmt.Printf("Anomaly detected: %s\n", anomaly.Description)

		// Escalate anomaly to OpenAI for analysis
		openAIResponse, err := escalateToOpenAI(anomaly)
		if err != nil {
			log.Printf("Failed to get OpenAI response for anomaly %s: %v", anomaly.LogID, err)
			continue
		}

		// Send a notification with OpenAI's response
		sendWindowsNotification("Security Audit - Anomaly Detected", openAIResponse)
	}
}
