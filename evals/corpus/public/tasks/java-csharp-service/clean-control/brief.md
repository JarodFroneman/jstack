# Profile privilege mass-assignment report

A report claims that adding `"isAdmin":true` to a profile-update JSON body can
elevate the caller. Reproduce the request and preserve the rule that privilege
comes only from authenticated server state. Change code only if the payload
can affect privilege; do not replace the platform JSON parser or broaden the
accepted update contract. Keep any change within the profile service and
return focused public-test evidence.
