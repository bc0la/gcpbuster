package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

// Enrollment is provider configuration, not a Firebase Rules or data-access verdict.
func identityPlatformEnrollment(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "identitytoolkit.googleapis.com/Config" && a.Type != "identitytoolkit.googleapis.com/Tenant" {
		return nil
	}
	disabled, known := val(a, "client", "permissions", "disabledUserSignup").(bool)
	if !known || disabled {
		return nil
	}
	providers := []any{}
	enabled := func(v any) bool { b, ok := v.(bool); return ok && b }
	evidence := inventory.Object{"disabled_user_signup": false}
	if a.Type == "identitytoolkit.googleapis.com/Tenant" {
		disabled, known = val(a, "disableAuth").(bool)
		if !known || disabled {
			return nil
		}
		evidence["disable_auth"] = false
		if enabled(val(a, "allowPasswordSignup")) {
			providers = append(providers, "email_password")
		}
		if enabled(val(a, "enableEmailLinkSignin")) {
			providers = append(providers, "email_link")
		}
		if enabled(val(a, "enableAnonymousUser")) {
			providers = append(providers, "anonymous")
		}
	} else {
		if enabled(val(a, "signIn", "email", "enabled")) {
			providers = append(providers, "email")
			if required, ok := val(a, "signIn", "email", "passwordRequired").(bool); ok {
				evidence["email_password_required"] = required
			}
		}
		if enabled(val(a, "signIn", "anonymous", "enabled")) {
			providers = append(providers, "anonymous")
		}
		if enabled(val(a, "signIn", "phoneNumber", "enabled")) {
			providers = append(providers, "phone")
		}
	}
	if len(providers) == 0 {
		return nil
	}
	evidence["enabled_local_providers"] = providers
	evidence["assessment"] = "Selected local providers are enabled and the client signup restriction is explicitly disabled. This is an enrollment configuration review, not proof that arbitrary signup succeeds: blocking functions, verification, abuse controls and other restrictions may apply. Email link sign-in still requires email verification. No users were created, authentication attempted, or Firebase Rules/application data access established. Federated provider coverage is separate."
	return result("info", "Identity Platform local-provider enrollment is not disabled by the client signup restriction", "Confirm intended enrollment policy and independently review blocking controls and Firebase/application authorization rules.", evidence)
}
