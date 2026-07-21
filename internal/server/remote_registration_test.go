package server

import "testing"

func TestNormalizeRemoteImportURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "host and admin path", in: "grok.example.com/admin/api/", want: "https://grok.example.com"},
		{name: "uppercase and query", in: "HTTPS://grok.example.com/admin?stale=1", want: "https://grok.example.com"},
		{name: "empty", in: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRemoteImportURL(tc.in)
			if err != nil {
				t.Fatalf("normalizeRemoteImportURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeRemoteImportURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	for _, in := range []string{"ftp://grok.example.com", "https://"} {
		if _, err := normalizeRemoteImportURL(in); err == nil {
			t.Fatalf("normalizeRemoteImportURL(%q) accepted an invalid URL", in)
		}
	}
}
