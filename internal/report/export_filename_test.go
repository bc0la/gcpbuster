package report

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExportFilenamesFollowSelectionSafely(t *testing.T) {
	e := exportServerEngagement(t)
	h := Handler(e)
	for _, tt := range []struct{ path, selection, suffix string }{
		{"/api/export/json", "all", ".json"},
		{"/api/export/assets?category=iam", "iam", "-assets.txt"},
		{"/api/export/json?category=iam&module=iam_permission_risks", "iam_permission_risks", ".json"},
		{"/api/export/json?module=" + url.QueryEscape(`bad";filename=unsafe`), "all", ".json"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", tt.path, nil))
		if w.Code != 200 || w.Header().Get("Content-Disposition") != `attachment; filename="gcpbuster-`+tt.selection+tt.suffix+`"` {
			t.Fatal(tt.path, w.Code, w.Header())
		}
		if strings.Contains(w.Header().Get("Content-Disposition"), "unsafe") {
			t.Fatal("unsafe filename")
		}
	}
}
