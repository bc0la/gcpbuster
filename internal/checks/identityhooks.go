package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func identityBlockingFunctions(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "identitytoolkit.googleapis.com/Config" {
		return nil
	}
	d := obj(val(a, "_gcpbusterIdentityHooks"))
	if complete, ok := d["complete"].(bool); !ok || !complete {
		return nil
	}
	hooks := []any{}
	for _, event := range []string{"beforeCreate", "beforeSignIn"} {
		if flag, ok := obj(d["hooks"])[event].(bool); ok && flag {
			hooks = append(hooks, event)
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	forwarded := []any{}
	for _, key := range []string{"idToken", "accessToken", "refreshToken"} {
		if flag, ok := obj(d["forward_credentials"])[key].(bool); ok && flag {
			forwarded = append(forwarded, key)
		}
	}
	return result("info", "Identity Platform registers blocking authentication hooks", "Review hook ownership, deployed code and any enabled inbound credential forwarding. Hook presence is neither an authentication bypass nor proof that enrollment is blocked.", inventory.Object{"configured_events": hooks, "forwarded_credential_types": forwarded, "assessment": "Project configuration only, including tenant users where supported. Hook code, destination ownership, availability and enforcement were not evaluated. Anonymous and custom authentication do not support blocking functions. Enabled flags describe forwarding of upstream identity-provider credentials, not actual token values or a proven credential leak. No hook URL, user, credential, function source or application request was retained or accessed."})
}
