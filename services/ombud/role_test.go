package main

import (
	"net/http/httptest"
	"testing"
)

// TestOmbudRoleHeaderDevOnly (audit fix H-2): X-Ombud-Role grants
// institutional roles only in dev mode; in keycloak mode it is ignored and
// the role derives from verified token claims.
func TestOmbudRoleHeaderDevOnly(t *testing.T) {
	s := newTestServer(t)

	// dev mode: header is honored
	s.cfg.AuthMode = "dev"
	s.authn = newAuthenticator(s.cfg)
	r := httptest.NewRequest("GET", "/v1/cases", nil)
	r.Header.Set("X-Ombud-Role", RoleRegistry)
	p := &Principal{Sub: "u", Roles: []string{"operator"}}
	if got := s.roleOf(r, p); got != RoleRegistry {
		t.Fatalf("dev mode: want %q from header, got %q", RoleRegistry, got)
	}

	// keycloak mode: header is ignored, claims win
	s.cfg.AuthMode = "keycloak"
	s.authn = newAuthenticator(s.cfg)
	if got := s.roleOf(r, p); got != RoleClerk {
		t.Fatalf("keycloak mode: want %q from claims (header ignored), got %q", RoleClerk, got)
	}
	// a principal with no mapped roles must not self-assign registry
	p2 := &Principal{Sub: "u2", Roles: []string{"auditor"}}
	if got := s.roleOf(r, p2); got != RoleMember {
		t.Fatalf("keycloak mode: want %q, got %q", RoleMember, got)
	}
}
