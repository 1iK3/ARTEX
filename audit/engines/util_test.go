package engines

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRedactEngineText(t *testing.T) {
	backslash := string(rune(92))
	unc := backslash + backslash + "fileserver" + backslash + "share" + backslash + "cpg.bin"
	message := "failed at C:/Users/alice/AppData/Local/Temp/job/stderr.log and " +
		"D:/tools/joern/joern-cli/joern.bat and /home/alice/repo and " + unc
	redacted := RedactEngineText(message)
	for _, forbidden := range []string{
		"C:/Users/alice", "AppData", "D:/tools", "joern-cli", "/home/alice", "fileserver",
	} {
		if strings.Contains(redacted, forbidden) {
			t.Fatalf("RedactEngineText leaked %q: %s", forbidden, redacted)
		}
	}
	if !strings.Contains(redacted, "[redacted-path]") {
		t.Fatalf("RedactEngineText did not leave a marker: %s", redacted)
	}
	if got := RedactEngineText("no paths here"); got != "no paths here" {
		t.Fatalf("plain text changed: %q", got)
	}
}

func TestClassifyExecErrorRedactsStderrSecrets(t *testing.T) {
	stderr := strings.Join([]string{
		"failed at /opt/artex/tasks/9/audit/source",
		"api_key = abcdef123456",
		"Authorization: Bearer abcdefghijklmnop",
		"AKIA0123456789ABCDEF",
		"-----BEGIN RSA PRIVATE KEY-----\nsecretbody\n-----END RSA PRIVATE KEY-----",
	}, "\n")

	err := classifyExecError(context.Background(), errors.New("query failed"), stderr)
	if err == nil {
		t.Fatal("classifyExecError returned nil")
	}
	message := err.Error()
	for _, forbidden := range []string{
		"/opt/artex", "abcdef123456", "abcdefghijklmnop", "AKIA0123456789ABCDEF",
		"BEGIN RSA PRIVATE KEY", "secretbody",
	} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("classified error leaked %q: %s", forbidden, message)
		}
	}
	if !strings.Contains(message, "query failed") || !strings.Contains(message, "[redacted-path]") {
		t.Fatalf("classified error lost diagnostics: %s", message)
	}
}
