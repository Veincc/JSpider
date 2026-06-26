//go:build cgo

package headless

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Veincc/JSpider/internal/apidiscovery"
	"github.com/Veincc/JSpider/internal/logging"
)

func TestAPIDiscoveryClickConfirmsGatewayPrefix(t *testing.T) {
	if os.Getenv("JSPIDER_HEADLESS_TEST") != "1" {
		t.Skip("Set JSPIDER_HEADLESS_TEST=1 to run headless API integration tests")
	}
	if err := CheckBrowserAvailable(); err != nil {
		t.Skipf("Chrome/Chromium unavailable: %v", err)
	}

	const source = `
		function staticApiShape() { return fetch("/user/list"); }
		const endpoint = "/user/list";
		const button = document.getElementById("load-users");
		button.onclick = () => fetch(button.dataset.prefix + endpoint + "?page=1");
	`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<button id="load-users" data-prefix="/gw">Load users</button><script src="/app.js"></script>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(source))
		case "/gw/user/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	log := logging.New(false, t.TempDir())
	defer log.Close()
	result, err := DiscoverWithRuntime(context.Background(), &Config{
		EntryURL:   server.URL + "/",
		Timeout:    12 * time.Second,
		SameOrigin: true,
		MaxClicks:  5,
		CaptureAPI: true,
	}, log)
	if err != nil {
		t.Fatalf("DiscoverWithRuntime() error = %v", err)
	}
	static, err := apidiscovery.AnalyzeJavaScript([]byte(source), server.URL+"/app.js")
	if err != nil {
		t.Fatal(err)
	}
	report := apidiscovery.BuildReport(static, result.Requests)
	if len(report.Bases) != 1 || report.Bases[0].RuntimeBase != server.URL+"/gw" ||
		report.Bases[0].Confidence != apidiscovery.ConfidenceConfirmed {
		t.Fatalf("runtime bases = %+v", report.Bases)
	}
}
