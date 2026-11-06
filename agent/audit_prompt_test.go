package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRenderAuditIntentTaskIncludesAuditMethodology(t *testing.T) {
	intent := &db.Node{
		ID:      42,
		Payload: json.RawMessage(`{"title":"Decoder error contract","query_kind":"error_contract"}`),
	}

	prompt := renderAuditIntentTask(intent)
	for _, want := range []string{
		"审计方法论",
		"入口点和攻击者可控输入",
		"状态机与错误契约",
		"宏展开",
		"调用方契约",
		"重试循环",
		"固定大小缓冲",
		"反证",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("audit worker prompt missing %q:\n%s", want, prompt)
		}
	}
}
