package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeRequiresSingleObject(t *testing.T) {
	for _, body := range []string{`null`, `{} true`, `{} ]`, `{} {}`} {
		t.Run(body, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			w := httptest.NewRecorder()
			var in struct {
				Name string `json:"name"`
			}
			if decode(w, r, &in) {
				t.Fatal("accepted non-object or trailing data")
			}
		})
	}
}
