# Profile-name HTML report

A security report claims that a display name containing HTML can introduce
executable markup into the profile-name fragment. Reproduce the report against
the renderer and preserve the documented HTML-encoding behaviour. Make a
change only if unsafe markup can reach the fragment; do not add a second
encoding layer or alter valid text unnecessarily. Keep any change within the
renderer and return focused public-test evidence.
