package engines

import (
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
