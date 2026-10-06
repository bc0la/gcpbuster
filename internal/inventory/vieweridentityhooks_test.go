package inventory

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestViewerIdentityBlockingFunctionsProjectionAndMalformedSiblings(t *testing.T) {
	d := Object{"name": "projects/123/config", "signIn": Object{"email": Object{"enabled": true}}, "blockingFunctions": Object{"triggers": Object{"beforeCreate": Object{"functionUri": "https://private.example.test/hook?secret=PRIVATE_TOKEN", "updateTime": "PRIVATE_TIMESTAMP"}}, "forwardInboundCredentials": Object{"idToken": true, "accessToken": false, "refreshToken": true, "unexpected": "PRIVATE_VALUE"}}}
	clean, err := viewerIdentityPosture(d)
	if err != nil || Get(clean, "_gcpbusterIdentityHooks", "complete") != true || Get(clean, "_gcpbusterIdentityHooks", "hooks", "beforeCreate") != true || Get(clean, "_gcpbusterIdentityHooks", "forward_credentials", "refreshToken") != true {
		t.Fatal(clean, err)
	}
	b, _ := json.Marshal(clean)
	if bytes.Contains(b, []byte("PRIVATE_")) || bytes.Contains(b, []byte("example.test")) || bytes.Contains(b, []byte("functionUri")) {
		t.Fatal("private hook details retained", string(b))
	}
	Obj(Obj(d["blockingFunctions"])["triggers"])["beforeSignIn"] = Object{"functionUri": "not-a-uri"}
	clean, err = viewerIdentityPosture(d)
	if err == nil || Get(clean, "_gcpbusterIdentityHooks", "complete") != false || Get(clean, "_gcpbusterIdentityHooks", "hooks", "beforeCreate") != true || Get(clean, "signIn", "email", "enabled") != true {
		t.Fatal("malformed hook lost valid siblings or became complete", clean, err)
	}
}

func TestViewerIdentityBlockingFunctionsUnknownIsNotAbsence(t *testing.T) {
	for _, raw := range []any{nil, true, Object{"triggers": true}, Object{"triggers": Object{"unsupported": Object{"functionUri": "https://example.test"}}}, Object{"forwardInboundCredentials": Object{"refreshToken": "true"}}} {
		got, err := viewerIdentityBlockingFunctions(raw)
		if err == nil || got["complete"] != false {
			t.Fatal(raw, got, err)
		}
	}
	got, err := viewerIdentityBlockingFunctions(Object{"triggers": Object{}})
	if err != nil || got["complete"] != true || len(Obj(got["hooks"])) != 0 {
		t.Fatal(got, err)
	}
}
