package options

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	ErrFileTooLarge    = errors.New("file too large")
	ErrFileOpen        = errors.New("could not open file")
	ErrFileRead        = errors.New("error reading file")
	ErrLineTooLong     = errors.New("line exceeds maximum length")
	DefaultMaxFileSize = int64(100 * 1024 * 1024) // 100MB
	DefaultMaxLineSize = 8192
)

// FileHandler handles file operations with proper error handling
type FileHandler struct {
	maxLineLength int
	maxFileSize   int64
}

// NewFileHandler creates a new FileHandler with default limits
func NewFileHandler() *FileHandler {
	return &FileHandler{
		maxLineLength: DefaultMaxLineSize,
		maxFileSize:   DefaultMaxFileSize,
	}
}

// SetMaxFileSize sets the maximum file size limit
func (fh *FileHandler) SetMaxFileSize(size int64) {
	fh.maxFileSize = size
}

// SetMaxLineSize sets the maximum line length
func (fh *FileHandler) SetMaxLineSize(size int) {
	fh.maxLineLength = size
}

// ReadLines reads lines from a file safely
func (fh *FileHandler) ReadLines(filename string) ([]string, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFileOpen, err)
	}
	defer file.Close()

	// Check file size
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("getting file info: %w", err)
	}
	if stat.Size() > fh.maxFileSize {
		return nil, fmt.Errorf("%w: %d bytes (max: %d)",
			ErrFileTooLarge, stat.Size(), fh.maxFileSize)
	}

	var lines []string
	scanner := bufio.NewScanner(file)

	// Set buffer size for long lines
	buffer := make([]byte, fh.maxLineLength)
	scanner.Buffer(buffer, fh.maxLineLength)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !isComment(line) {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w at line %d: %w", ErrFileRead, lineNum, err)
	}

	return lines, nil
}

// ReadLinesFromReader reads lines from an io.Reader
func (fh *FileHandler) ReadLinesFromReader(reader io.Reader) ([]string, error) {
	if reader == nil {
		return nil, errors.New("nil reader")
	}

	var lines []string
	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, fh.maxLineLength)
	scanner.Buffer(buffer, fh.maxLineLength)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !isComment(line) {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w at line %d: %w", ErrFileRead, lineNum, err)
	}

	return lines, nil
}

// SafeWriteFile writes content to a file with proper permissions
func SafeWriteFile(filename string, content string) error {
	if filename == "" {
		return errors.New("empty filename")
	}

	// Use 0600 - owner read/write only (no magic number)
	const filePerm = 0600

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// isComment checks if a line is a comment
func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, ";")
}
