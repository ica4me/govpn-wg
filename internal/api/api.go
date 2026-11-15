// Package api exposes the engine over a JSON REST API under /api/v1.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/generator"
	"github.com/ica4me/govpn-wg/internal/sysopt"
)

// Version is set at build time with -ldflags "-X .../api.Version=...".
var Version = "dev"

type Server struct {
	eng   *engine.Engine
	auth  *Auth
	log   *slog.Logger
	tune  func() sysopt.Report
	start time.Time
}

func New(eng *engine.Engine, auth *Auth, log *slog.Logger, tune func() sysopt.Report) *Server {
	return &Server{eng: eng, auth: auth, log: log, tune: tune, start: time.Now()}
}

// Handler builds the router. Go 1.22+ ServeMux handles methods and wildcards.
func (s *Server) Handler() http.Handler {
	pub := http.NewServeMux()
	pub.HandleFunc("GET /api/v1/health", s.health)
	pub.HandleFunc("POST /api/v1/auth/login", s.login)

	p := http.NewServeMux()
	p.HandleFunc("POST /api/v1/auth/password", s.changePassword)
	p.HandleFunc("GET /api/v1/system/status", s.status)
	p.HandleFunc("POST /api/v1/system/tune", s.runTune)
	p.HandleFunc("POST /api/v1/system/reconcile", s.reconcile)

	p.HandleFunc("GET /api/v1/sites", s.listSites)
	p.HandleFunc("POST /api/v1/sites", s.createSite)
	p.HandleFunc("GET /api/v1/sites/{id}", s.getSite)
	p.HandleFunc("PUT /api/v1/sites/{id}", s.updateSite)
	p.HandleFunc("DELETE /api/v1/sites/{id}", s.deleteSite)
	p.HandleFunc("GET /api/v1/sites/{id}/download/{kind}", s.downloadSite)

	p.HandleFunc("GET /api/v1/groups", s.listGroups)
	p.HandleFunc("POST /api/v1/groups", s.createGroup)
	p.HandleFunc("PUT /api/v1/groups/{id}", s.updateGroup)
	p.HandleFunc("DELETE /api/v1/groups/{id}", s.deleteGroup)

	p.HandleFunc("GET /api/v1/clients", s.listClients)
	p.HandleFunc("POST /api/v1/clients", s.createClient)
	p.HandleFunc("GET /api/v1/clients/{id}", s.getClient)
	p.HandleFunc("PUT /api/v1/clients/{id}", s.updateClient)
	p.HandleFunc("DELETE /api/v1/clients/{id}", s.deleteClient)
	p.HandleFunc("GET /api/v1/clients/{id}/download/{kind}", s.downloadClient)

	protected := s.auth.middleware(p)
	root := http.NewServeMux()
	root.Handle("/api/v1/health", pub)
	root.Handle("POST /api/v1/auth/password", protected)
	root.Handle("/api/v1/auth/", pub)
	root.Handle("/api/", protected)
	return s.logRequests(securityHeaders(root))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: 200}
		t := time.Now()
		next.ServeHTTP(sw, r)
		s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.code, "ms", time.Since(t).Milliseconds(), "remote", remoteIP(r))
	})
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	code := engine.StatusOf(err)
	msg := err.Error()
	if code == http.StatusInternalServerError {
		s.log.Error("internal error", "err", err)
		msg = "internal error"
	}
	writeError(w, code, msg)
}

// decode reads a JSON object strictly: unknown fields and trailing data fail.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "request body must be a JSON object")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if len(raw) == 0 || raw[0] != '{' {
		writeError(w, http.StatusBadRequest, "request body must be a JSON object")
		return false
	}
	obj := json.NewDecoder(bytes.NewReader(raw))
	obj.DisallowUnknownFields()
	if err := obj.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "trailing data after JSON object")
		return false
	}
	return true
}

func attachment(w http.ResponseWriter, name, ctype, body string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

// --- public ----------------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "version": Version})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	tok, exp, err := s.auth.Login(in.Username, in.Password, remoteIP(r))
	switch {
	case errors.Is(err, errRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		s.log.Warn("login failed", "remote", remoteIP(r))
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_at": exp.UTC()})
}

// --- system ----------------------------------------------------------------

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	last, lastErr := s.eng.LastSync()
	st := s.eng.Snapshot()
	cfg := s.eng.Config()
	lan := make([]string, 0, len(cfg.ServerLAN))
	for _, p := range cfg.ServerLAN {
		lan = append(lan, p.String())
	}
	online := 0
	for _, v := range s.eng.ListSites() {
		if v.Runtime.Status == "online" {
			online++
		}
	}
	clientsOnline := 0
	for _, v := range s.eng.ListClients() {
		if v.Runtime.Status == "online" {
			clientsOnline++
		}
	}
	writeJSON(w, 200, map[string]any{
		"version": Version, "uptime_seconds": int(time.Since(s.start).Seconds()),
		"endpoint": s.eng.Endpoint(), "public_interface": s.eng.PublicIf(),
		"server_lan": lan, "default_mtu": cfg.DefaultMTU, "base_port": cfg.BasePort, "mss_mode": cfg.MSSMode,
		"sites": len(st.Sites), "sites_online": online, "groups": len(st.Groups),
		"clients": len(st.Clients), "clients_online": clientsOnline,
		"last_apply": last.UTC(), "last_apply_error": lastErr,
	})
}

func (s *Server) runTune(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.tune())
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	if err := s.eng.Reconcile(); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// --- sites -----------------------------------------------------------------

func (s *Server) listSites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.eng.ListSites())
}

func (s *Server) getSite(w http.ResponseWriter, r *http.Request) {
	v, err := s.eng.GetSite(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var in engine.SiteInput
	if !decode(w, r, &in) {
		return
	}
	if in.RotateKeys {
		writeError(w, 422, "rotate_keys is only valid on update")
		return
	}
	site, err := s.eng.CreateSite(in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.eng.SiteViewOf(site))
}

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	var in engine.SiteInput
	if !decode(w, r, &in) {
		return
	}
	site, err := s.eng.UpdateSite(r.PathValue("id"), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, s.eng.SiteViewOf(site))
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	if err := s.eng.DeleteSite(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) downloadSite(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	p, err := s.eng.SitePeer(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	switch kind {
	case "linux":
		text, err := generator.SiteScript(p)
		if err != nil {
			s.fail(w, err)
			return
		}
		attachment(w, "install-site-"+p.FileName+".sh", "text/x-shellscript; charset=utf-8", text)
	case "windows", "conf":
		text, err := generator.Conf(p)
		if err != nil {
			s.fail(w, err)
			return
		}
		attachment(w, "site-"+p.FileName+".conf", "text/plain; charset=utf-8", text)
	default:
		writeError(w, http.StatusNotFound, "download kind must be linux or windows")
	}
}

// --- groups ----------------------------------------------------------------

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.eng.ListGroups())
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in engine.GroupInput
	if !decode(w, r, &in) {
		return
	}
	g, err := s.eng.CreateGroup(in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.eng.GroupViewOf(g))
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var in engine.GroupInput
	if !decode(w, r, &in) {
		return
	}
	g, err := s.eng.UpdateGroup(r.PathValue("id"), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, s.eng.GroupViewOf(g))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.eng.DeleteGroup(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- clients ---------------------------------------------------------------

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.eng.ListClients())
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) {
	v, err := s.eng.GetClient(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var in engine.ClientInput
	if !decode(w, r, &in) {
		return
	}
	if in.RotateKeys {
		writeError(w, 422, "rotate_keys is only valid on update")
		return
	}
	c, err := s.eng.CreateClient(in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.eng.ClientViewOf(c))
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	var in engine.ClientInput
	if !decode(w, r, &in) {
		return
	}
	c, err := s.eng.UpdateClient(r.PathValue("id"), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, s.eng.ClientViewOf(c))
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := s.eng.DeleteClient(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) downloadClient(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	p, err := s.eng.ClientPeer(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	switch kind {
	case "linux":
		text, err := generator.ClientScript(p)
		if err != nil {
			s.fail(w, err)
			return
		}
		attachment(w, "config-"+p.FileName+".sh", "text/x-shellscript; charset=utf-8", text)
	case "conf":
		text, err := generator.Conf(p)
		if err != nil {
			s.fail(w, err)
			return
		}
		attachment(w, p.FileName+".conf", "text/plain; charset=utf-8", text)
	case "qr":
		text, err := generator.Conf(p)
		if err != nil {
			s.fail(w, err)
			return
		}
		png, err := generator.QR(text)
		if err != nil {
			s.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s.png"`, p.FileName))
		_, _ = w.Write(png)
	default:
		writeError(w, http.StatusNotFound, "download kind must be linux, conf or qr")
	}
}
