use hyp_node::engine::node::{KvInspection, KvKeyPage, KvNamespaceInspection, KvValuePreview};
use serde_json::Value;

use super::{compute_window, format_age_ms, render_selectable_row, truncate_plain};

#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use hyp_harness::local_kv::{LocalKvAction, LocalKvRequest, LocalKvResponse};

#[derive(Debug, Default, Clone)]
pub(super) struct KvBrowser {
    local: Vec<KvNamespaceInspection>,
    peers: Vec<KvNamespaceInspection>,
    local_truncated: bool,
    peers_truncated: bool,
    opened: Option<OpenNamespace>,
    preview: Option<(String, KvValuePreview)>,
}

#[derive(Debug, Clone)]
struct OpenNamespace {
    origin: String,
    name: String,
    page: KvKeyPage,
    cursors: Vec<Option<String>>,
}

impl KvBrowser {
    pub(super) fn apply_local_snapshot(&mut self, value: &Value, node_id: &str) {
        let inspection = serde_json::from_value::<KvInspection>(value.clone()).ok();
        self.local_truncated = inspection
            .as_ref()
            .is_some_and(|report| report.namespaces_truncated);
        self.local = inspection
            .map(|report| report.namespaces)
            .unwrap_or_default();
        if self.opened.as_ref().is_some_and(|opened| {
            opened.origin == node_id
                && !self
                    .local
                    .iter()
                    .any(|namespace| namespace.name == opened.name)
        }) {
            self.close();
        }
    }

    pub(super) fn close(&mut self) {
        self.opened = None;
        self.preview = None;
    }

    fn namespaces(&self) -> impl Iterator<Item = &KvNamespaceInspection> {
        self.local.iter().chain(&self.peers)
    }

    pub(super) fn row_count(&self) -> usize {
        if let Some((_, preview)) = &self.preview {
            return preview.text.lines().count().max(1);
        }
        if let Some(opened) = &self.opened {
            return opened.page.entries.len();
        }
        self.local.len() + self.peers.len()
    }

    pub(super) fn render(
        &self,
        selected: usize,
        now_ms: i64,
        budget: usize,
        cols: usize,
        use_color: bool,
    ) -> Vec<String> {
        if let Some((key, preview)) = &self.preview {
            let suffix = if preview.truncated {
                " · truncated"
            } else {
                ""
            };
            let mut lines = vec![truncate_plain(
                &format!("{key} · v{}{suffix}", preview.version),
                cols,
            )];
            let text: Vec<_> = preview.text.lines().collect();
            let (start, end) = compute_window(selected, text.len(), budget.saturating_sub(1));
            lines.extend(
                text[start..end]
                    .iter()
                    .map(|line| truncate_plain(line, cols)),
            );
            return lines;
        }

        let (header, content): (String, Vec<String>) = if let Some(opened) = &self.opened {
            let title = format!("{}/{}", opened.origin, opened.name);
            let mut header = format!("{title} · key  version  writer  age  TTL  size");
            if opened.page.next_after.is_some() {
                header.push_str(" · n for more");
            }
            let rows = opened
                .page
                .entries
                .iter()
                .map(|entry| {
                    let age = format_age_ms(entry.updated_at, now_ms);
                    let ttl = entry
                        .expires_at
                        .map(|at| format_age_ms(now_ms, at))
                        .unwrap_or_else(|| "—".into());
                    format!(
                        "{}  v{}  {}  {}  {}  {} B",
                        entry.key, entry.version, entry.updated_by, age, ttl, entry.size_bytes
                    )
                })
                .collect();
            (header, rows)
        } else {
            let header = if self.local_truncated || self.peers_truncated {
                "KV namespaces · listing truncated"
            } else {
                "KV namespaces"
            };
            let rows = self
                .namespaces()
                .map(|namespace| {
                    let security = namespace
                        .epoch
                        .map(|epoch| format!("E2EE e{epoch} · {} members", namespace.member_count))
                        .unwrap_or_else(|| "plaintext".into());
                    format!(
                        "{}/{}  {} keys  {} watches  {security}",
                        namespace.origin_node,
                        namespace.name,
                        namespace.entry_count,
                        namespace.watch_count
                    )
                })
                .collect();
            (header.to_owned(), rows)
        };
        let mut lines = vec![truncate_plain(&header, cols)];
        if content.is_empty() && budget > 1 {
            lines.push(truncate_plain("No visible KV records.", cols));
            return lines;
        }
        let (start, end) = compute_window(selected, content.len(), budget.saturating_sub(1));
        lines.extend((start..end).map(|index| {
            render_selectable_row(&content[index], selected == index, cols, use_color)
        }));
        lines
    }
}

#[cfg(unix)]
impl KvBrowser {
    pub(super) fn refresh(&mut self, socket: &Path, local_node: &str) -> bool {
        let response = self.request(socket, "local", "", LocalKvAction::Inspect);
        let Some(LocalKvResponse::Inspect(report)) = response else {
            self.peers.clear();
            self.peers_truncated = false;
            self.close();
            return false;
        };
        self.local.clear();
        self.peers.clear();
        self.local_truncated = false;
        self.peers_truncated = report.namespaces_truncated;
        for namespace in report.namespaces {
            if namespace.origin_node == local_node {
                self.local.push(namespace);
            } else {
                self.peers.push(namespace);
            }
        }
        self.preview = None;
        if let Some(opened) = &self.opened {
            if self
                .namespaces()
                .any(|ns| ns.origin_node == opened.origin && ns.name == opened.name)
            {
                if !self.refresh_open_page(socket, None) {
                    self.close();
                    return false;
                }
            } else {
                self.close();
            }
        }
        true
    }

    pub(super) fn refresh_open_page(&mut self, socket: &Path, only_origin: Option<&str>) -> bool {
        let Some(opened) = &mut self.opened else {
            return true;
        };
        if only_origin.is_some_and(|origin| origin != opened.origin) {
            return true;
        }
        let after = opened.cursors.last().cloned().flatten();
        let Some(page) = Self::get_keys(socket, &opened.origin, &opened.name, after) else {
            self.close();
            return false;
        };
        if self.preview.as_ref().is_some_and(|(key, preview)| {
            !page
                .entries
                .iter()
                .any(|entry| entry.key == *key && entry.version == preview.version)
        }) {
            self.preview = None;
        }
        opened.page = page;
        true
    }

    pub(super) fn open_selected(&mut self, socket: &Path, row: usize) -> bool {
        if self.preview.is_some() {
            return true;
        }
        if let Some(opened) = &self.opened {
            let Some(key) = opened.page.entries.get(row).map(|entry| entry.key.clone()) else {
                return false;
            };
            let Some(LocalKvResponse::Preview(Some(preview))) = self.request(
                socket,
                &opened.origin,
                &opened.name,
                LocalKvAction::Preview { key: key.clone() },
            ) else {
                return false;
            };
            self.preview = Some((key, preview));
            return true;
        }
        let Some(namespace) = self.namespaces().nth(row) else {
            return false;
        };
        let Some(page) = Self::get_keys(socket, &namespace.origin_node, &namespace.name, None)
        else {
            return false;
        };
        self.opened = Some(OpenNamespace {
            origin: namespace.origin_node.clone(),
            name: namespace.name.clone(),
            page,
            cursors: vec![None],
        });
        true
    }

    pub(super) fn back(&mut self) {
        if self.preview.take().is_none() {
            self.opened = None;
        }
    }

    pub(super) fn page(&mut self, socket: &Path, next: bool) -> bool {
        let Some(opened) = &mut self.opened else {
            return false;
        };
        if self.preview.is_some() {
            return false;
        }
        let after = if next {
            let Some(after) = opened.page.next_after.clone() else {
                return false;
            };
            Some(after)
        } else {
            let Some(index) = opened.cursors.len().checked_sub(2) else {
                return false;
            };
            opened.cursors[index].clone()
        };
        let Some(page) = Self::get_keys(socket, &opened.origin, &opened.name, after.clone()) else {
            return false;
        };
        if next {
            opened.cursors.push(after);
        } else {
            opened.cursors.pop();
        }
        opened.page = page;
        true
    }

    fn get_keys(
        socket: &Path,
        origin: &str,
        namespace: &str,
        after: Option<String>,
    ) -> Option<KvKeyPage> {
        let request = LocalKvRequest {
            host_node: origin.to_owned(),
            namespace: namespace.to_owned(),
            action: LocalKvAction::Keys { after },
        };
        match crate::kv_cmd::request_live_kv(socket, &request)? {
            LocalKvResponse::Keys(page) => Some(page),
            _ => None,
        }
    }

    fn request(
        &self,
        socket: &Path,
        origin: &str,
        namespace: &str,
        action: LocalKvAction,
    ) -> Option<LocalKvResponse> {
        crate::kv_cmd::request_live_kv(
            socket,
            &LocalKvRequest {
                host_node: origin.to_owned(),
                namespace: namespace.to_owned(),
                action,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_metadata_and_explicit_preview_fit_and_strip_terminal_controls() {
        let mut browser = KvBrowser::default();
        browser.apply_local_snapshot(
            &serde_json::json!({
                "namespaces": [{
                    "name": "shared",
                    "originNode": "local@host",
                    "epoch": 3,
                    "memberCount": 2,
                    "entryCount": 1,
                    "watchCount": 1,
                    "entries": []
                }],
                "namespacesTruncated": false
            }),
            "local@host",
        );
        let namespace_frame = browser.render(0, 60_000, 4, 80, false).join("\n");
        assert!(namespace_frame.contains("local@host/shared"));
        assert!(namespace_frame.contains("E2EE e3"));
        assert_eq!(browser.row_count(), 1);
        browser.opened = Some(OpenNamespace {
            origin: "local@host".into(),
            name: "shared".into(),
            page: serde_json::from_value(serde_json::json!({
                "entries": [{
                    "key": "key\u{202e}",
                    "version": 7,
                    "updatedBy": "peer@host",
                    "updatedAt": 30_000,
                    "expiresAt": 90_000,
                    "sizeBytes": 12
                }],
                "nextAfter": null
            }))
            .unwrap(),
            cursors: vec![None],
        });
        let key_frame = browser.render(0, 60_000, 4, 80, false).join("\n");
        assert!(key_frame.contains("key  v7  peer@host  30s  30s  12 B"));
        assert!(!key_frame.contains('\u{202e}'));
        browser.preview = Some((
            "key\u{202e}".into(),
            KvValuePreview {
                text: "visible\x1b[31m\nsecond\u{202e}".into(),
                version: 7,
                truncated: true,
            },
        ));
        let preview_frame = browser.render(0, 60_000, 3, 40, false);
        assert_eq!(preview_frame, ["key · v7 · truncated", "visible", "second"]);
        browser.close();
        assert!(browser.preview.is_none());
    }
}
