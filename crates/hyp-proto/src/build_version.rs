/// Resolve a release override consistently in both the CLI build script and the runtime.
pub fn resolve_build_version<'a>(override_version: Option<&'a str>, package: &'a str) -> &'a str {
    override_version
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .unwrap_or(package)
}
