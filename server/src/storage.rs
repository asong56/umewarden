use std::sync::LazyLock;

pub(crate) fn join_path(base: &str, child: &str) -> String {
    let base = base.trim_end_matches('/');
    let child = child.trim_start_matches('/');
    if base.is_empty() {
        child.to_owned()
    } else if child.is_empty() {
        base.to_owned()
    } else {
        format!("{base}/{child}")
    }
}

pub(crate) fn with_extension(path: &str, extension: &str) -> String {
    let extension = extension.trim_start_matches('.');
    format!("{path}.{extension}")
}

pub(crate) fn parent(path: &str) -> Option<String> {
    std::path::Path::new(path).parent()?.to_str().map(str::to_owned)
}

pub(crate) fn file_name(path: &str) -> Option<String> {
    std::path::Path::new(path).file_name()?.to_str().map(str::to_owned)
}

pub(crate) fn is_fs_operator(operator: &opendal::Operator) -> bool {
    operator.info().scheme() == opendal::services::FS_SCHEME
}

pub(crate) fn operator_for_path(path: &str) -> Result<opendal::Operator, crate::Error> {
    // Cache of previously built operators by path
    static OPERATORS_BY_PATH: LazyLock<dashmap::DashMap<String, opendal::Operator>> =
        LazyLock::new(dashmap::DashMap::new);

    if let Some(operator) = OPERATORS_BY_PATH.get(path) {
        return Ok(operator.clone());
    }

    if path.starts_with("s3://") {
        return Err(opendal::Error::new(
            opendal::ErrorKind::ConfigInvalid,
            "S3 storage is not supported in this build (local filesystem storage only)",
        )
        .into());
    }

    let builder = opendal::services::Fs::default().root(path);
    let operator = opendal::Operator::new(builder)?.finish();

    OPERATORS_BY_PATH.insert(path.to_owned(), operator.clone());

    Ok(operator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_local_paths() {
        assert_eq!(join_path("data", "attachments"), "data/attachments");
        assert_eq!(with_extension("data/rsa_key", "pem"), "data/rsa_key.pem");
        assert_eq!(parent("data/rsa_key.pem").as_deref(), Some("data"));
        assert_eq!(file_name("data/rsa_key.pem").as_deref(), Some("rsa_key.pem"));
    }
}
