package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// API serves session issuance and results reporting.
type API struct {
	store    *Store
	zone     string
	enricher Enricher
	probesV4 int
	probesV6 int
}

func (a *API) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/session", a.createSession)
	mux.HandleFunc("GET /v1/session/{token}/results", a.results)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

type sessionResponse struct {
	Token  string   `json:"token"`
	Zone   string   `json:"zone"`
	Probes []string `json:"probes"`
}

func (a *API) createSession(w http.ResponseWriter, r *http.Request) {
	sess := a.store.Create(a.zone, clientIP(r), a.probesV4, a.probesV6)
	writeJSON(w, http.StatusOK, sessionResponse{
		Token:  sess.Token,
		Zone:   a.zone,
		Probes: sess.Probes,
	})
}

type resultsResponse struct {
	Token             string         `json:"token"`
	ClientIP          string         `json:"client_ip"`
	ObservedResolvers []ResolverInfo `json:"observed_resolvers"`
	Count             int            `json:"count"`
}

func (a *API) results(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	sess, ok := a.store.Get(token)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	obs := sess.Observations()
	resolvers := make([]ResolverInfo, 0, len(obs))
	for _, o := range obs {
		resolvers = append(resolvers, a.enricher.Enrich(o.ResolverIP))
	}
	writeJSON(w, http.StatusOK, resultsResponse{
		Token:             token,
		ClientIP:          sess.ClientIP,
		ObservedResolvers: resolvers,
		Count:             len(resolvers),
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
