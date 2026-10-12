// Command oidcconformance drives OpenID Foundation relying-party plans against
// the client app's real token handling (internal/adapter/oidc). The suite plays
// the identity provider; this program plays the relying party: it signs in,
// reports whether the ID token was accepted, signs out, and answers the
// suite's back-channel logout requests. Run it through
// scripts/oidc-conformance.sh; see docs/deployment.md.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tewecske/goweb/internal/adapter/oidc"
)

const (
	alias    = "goweb"
	clientID = "goweb-conformance"
	secret   = "conformance-secret-0123456789"
	bcPath   = "/oauth/sso/backchannel-logout"
)

var (
	suite, listen, hostURL, issuer, redirect, postOut string

	api      = &http.Client{Timeout: 30 * time.Second}
	noFollow = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	mu       sync.Mutex
	current  *oidc.Client
	bcResult []string
)

func call(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = strings.NewReader(string(data))
	}
	request, _ := http.NewRequest(method, suite+path, reader)
	request.Header.Set("Content-Type", "application/json")
	response, err := api.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s: %s", err, string(data))
		}
	}
	return nil
}

type module struct {
	TestModule string            `json:"testModule"`
	Variant    map[string]string `json:"variant"`
}

type info struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

func waitFor(id string, want map[string]bool, d time.Duration) info {
	end := time.Now().Add(d)
	var i info
	for time.Now().Before(end) {
		_ = call("GET", "/api/info/"+id, nil, &i)
		if want[i.Status] {
			return i
		}
		time.Sleep(300 * time.Millisecond)
	}
	return i
}

func backChannel(writer http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	mu.Lock()
	client := current
	mu.Unlock()
	_, err := client.VerifyLogoutToken(request.Context(), request.PostForm.Get("logout_token"))
	writer.Header().Set("Cache-Control", "no-store")
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		bcResult = append(bcResult, "rejected: "+err.Error())
		http.Error(writer, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	bcResult = append(bcResult, "accepted")
	writer.WriteHeader(http.StatusOK)
}

func main() {
	planName := flag.String("plan", "", "test plan name, for example oidcc-client-basic-certification-test-plan")
	only := flag.String("module", "", "run a single module of the plan")
	flag.StringVar(&suite, "suite", "https://localhost.emobix.co.uk:8443", "conformance suite base URL")
	flag.StringVar(&listen, "listen", "172.20.0.1:8082", "address for the callback server, reachable from the suite container")
	flag.Parse()
	if *planName == "" {
		fmt.Fprintln(os.Stderr, "usage: oidcconformance -plan NAME [-module NAME]")
		os.Exit(2)
	}
	hostURL = "http://" + listen
	issuer = suite + "/test/a/" + alias + "/"
	redirect = hostURL + "/en/oauth/sso/callback"
	postOut = hostURL + "/en/sign-in"
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("POST "+bcPath, backChannel)
		server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := server.ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, "callback server:", err)
			os.Exit(1)
		}
	}()
	time.Sleep(300 * time.Millisecond)

	variant := `{"client_registration":"static_client","request_type":"plain_http_request"}`
	if strings.Contains(*planName, "logout") {
		variant = `{"client_registration":"static_client","request_type":"plain_http_request","client_auth_type":"client_secret_basic"}`
	}
	var plan struct {
		ID      string   `json:"id"`
		Modules []module `json:"modules"`
	}
	config := map[string]any{"alias": alias, "description": "goweb SSO client", "publish": "", "client": map[string]string{
		"client_id": clientID, "client_secret": secret, "redirect_uri": redirect,
		"post_logout_redirect_uri": postOut, "backchannel_logout_uri": hostURL + bcPath,
	}}
	if err := call("POST", "/api/plan?planName="+*planName+"&variant="+url.QueryEscape(variant), config, &plan); err != nil || plan.ID == "" {
		fmt.Println("plan error", err, plan)
		os.Exit(1)
	}
	for _, m := range plan.Modules {
		if *only != "" && m.TestModule != *only {
			continue
		}
		v, _ := json.Marshal(m.Variant)
		var run struct {
			ID string `json:"id"`
		}
		if err := call("POST", "/api/runner?test="+m.TestModule+"&plan="+plan.ID+"&variant="+url.QueryEscape(string(v)), nil, &run); err != nil || run.ID == "" {
			fmt.Println(m.TestModule, "runner error", err)
			continue
		}
		waitFor(run.ID, map[string]bool{"WAITING": true}, 15*time.Second)
		mu.Lock()
		bcResult = nil
		mu.Unlock()
		verdict := exercise()
		final := waitFor(run.ID, map[string]bool{"FINISHED": true, "INTERRUPTED": true}, 12*time.Second)
		mu.Lock()
		bc := strings.Join(bcResult, "; ")
		mu.Unlock()
		fmt.Printf("%-52s suite=%s/%s\n    client: %s\n", m.TestModule, final.Status, final.Result, verdict)
		if bc != "" {
			fmt.Printf("    back-channel: %s\n", bc)
		}
		var logs []map[string]any
		_ = call("GET", "/api/log/"+run.ID, nil, &logs)
		for _, entry := range logs {
			if r, _ := entry["result"].(string); r == "FAILURE" || r == "WARNING" {
				fmt.Printf("    suite %s: %v\n", r, entry["msg"])
			}
		}
		// Make sure the alias is free for the next module.
		if final.Status != "FINISHED" && final.Status != "INTERRUPTED" {
			_ = call("POST", "/api/runner/"+run.ID+"/cancel", nil, nil)
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func exercise() string {
	client, err := oidc.New(oidc.Config{Issuer: issuer, ClientID: clientID, ClientSecret: secret, RedirectURL: redirect})
	if err != nil {
		return "config: " + err.Error()
	}
	mu.Lock()
	current = client
	mu.Unlock()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target, err := client.AuthorizationURL(ctx, "state-123", challenge)
	if err != nil {
		return "authorization URL: " + err.Error()
	}
	response, err := noFollow.Get(target)
	if err != nil {
		return "authorize: " + err.Error()
	}
	response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.Header.Get("Location") == "" {
		return fmt.Sprintf("authorize: status %d without redirect", response.StatusCode)
	}
	code := location.Query().Get("code")
	if code == "" {
		return "authorize: no code in " + location.String()
	}
	if location.Query().Get("state") != "state-123" {
		return "authorize: state mismatch"
	}
	identity, err := client.Exchange(ctx, code, verifier)
	if err != nil {
		return "ID token REJECTED: " + err.Error()
	}
	out := "ID token accepted"
	endSession, err := client.EndSessionURL(ctx, identity.IDToken, postOut)
	if err != nil {
		return out + "; end session URL: " + err.Error()
	}
	response, err = noFollow.Get(endSession)
	if err != nil {
		return out + "; end_session: " + err.Error()
	}
	response.Body.Close()
	return fmt.Sprintf("%s; end_session -> %d %s", out, response.StatusCode, response.Header.Get("Location"))
}
