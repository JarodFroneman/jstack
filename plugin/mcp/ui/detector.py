"""Content-minimized Product Interface System applicability detection."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Iterable, Mapping


_PATH_RULES: tuple[tuple[str, str, str], ...] = (
    ("web", "web-component", r"\.(?:tsx|jsx|vue|svelte|astro|html?|css|scss|sass|less|styl|stylus|pcss|mdx|erb|ejs|hbs|handlebars|liquid|njk|nunjucks|twig|pug|razor|cshtml|aspx|jspx?|ftl|mustache)$"),
    ("web", "web-asset", r"(?:(^|/)(?:assets?|images?|icons?|public|static|fonts?|resources?)(/|$).*|^(?:logo(?:[._-].*)?|favicon(?:[._-].*)?|site\.webmanifest|manifest\.webmanifest|app-icon(?:[._-].*)?))\.(?:svgz?|png|jpe?g|webp|gif|avif|icns|ico|woff2?|ttf|otf|webmanifest)$|^(?:site|manifest)\.webmanifest$"),
    ("web", "web-route", r"^(?:app|pages|routes|views|components)(/|$)|(^|/)(?:web|website|frontend|client)(/|$)"),
    ("webview", "webview", r"(^|/)webview(/|[._-])"),
    ("electron", "electron-path", r"(^|/)(?:electron|main-process|renderer-process)(/|[._-])"),
    ("tauri", "tauri-path", r"(^|/)(?:src-tauri|tauri)(/|[._-])"),
    ("react-native", "react-native-path", r"(^|/)(?:react-native)(/|[._-])"),
    ("flutter", "flutter-path", r"(^|/)flutter(/|[._-])"),
    ("ios", "swift-ui-path", r"(^|/)(?:ios|swiftui|Assets\.xcassets)(/|[._-])|\.(?:xcodeproj|xcworkspace|storyboard|xib)$"),
    ("android", "compose-path", r"(^|/)(?:android|compose)(/|[._-])|(^|/)(?:[^/]+/)?src/main/(?:java|kotlin|res/(?:layout|values[^/]*|drawable[^/]*|mipmap[^/]*|font)|AndroidManifest\.xml)(/|$)|(^|/)[^/]+/build\.gradle(?:\.kts)?$"),
    ("macos", "mac-ui", r"(^|/)(?:macos|AppKit|SwiftUI)(/|[._-])"),
    ("windows", "windows-ui", r"\.(?:xaml|axaml)$"),
    ("linux", "linux-ui", r"(^|/)(?:gtk|qt)(/|[._-])|\.(?:ui|glade)$"),
)

_CONTENT_RULES: tuple[tuple[str, str, str], ...] = (
    ("web", "react", r"\b(?:React|useState|useEffect|createRoot)\b"),
    ("web", "angular", r"(?:from\s+['\"]@angular/|@Component\s*\()"),
    ("web", "lit-web-component", r"(?:from\s+['\"]lit(?:/|['\"])|\bLitElement\b|\bcustomElements\.define\s*\()"),
    ("web", "browser-dom", r"\b(?:document\s*\.|window\s*\.|HTMLElement|CSSStyleDeclaration)"),
    ("electron", "electron", r"\b(?:electron|BrowserWindow)\b"),
    ("tauri", "tauri", r"\b(?:@tauri-apps|tauri::)\b"),
    ("react-native", "react-native", r"\b(?:react-native|StyleSheet\.create|NativeModules)\b"),
    ("flutter", "flutter", r"\b(?:package:flutter|StatelessWidget|StatefulWidget)\b|\bsdk\s*:\s*flutter\b"),
    ("ios", "uikit", r"\b(?:UIKit|UIViewController|UIView)\b"),
    ("android", "android-view", r"\b(?:androidx\.compose|@Composable|com\.android\.application|setContentView|R\.layout\.|AppCompatActivity)\b|<\s*(?:(?-i:layout)\b|androidx\.)"),
    ("macos", "appkit", r"\b(?:AppKit|NSView|NSWindow)\b"),
    ("windows", "windows-app-sdk", r"\b(?:WinUI|WPF|Avalonia|Microsoft\.UI\.Xaml|System\.Windows(?:\.Forms)?|InitializeComponent)\b|<(?:UseWPF|UseWindowsForms)>\s*true\s*</(?:UseWPF|UseWindowsForms)>|Microsoft\.(?:WindowsAppSDK|NET\.Sdk\.(?:Razor|BlazorWebAssembly))"),
    ("linux", "gtk-qt", r"\b(?:Gtk|PyQt|PySide|QtWidgets|QApplication|QtQuick|ApplicationWindow|QWidget)\b|<ui\s+version="),
)

_SYSTEM_RULES: tuple[tuple[str, str], ...] = (
    ("design-tokens", r"(^|/)(?:tokens?|design-tokens?)(?:\.|/|$)"),
    ("storybook", r"(^|/)\.storybook(/|$)|\.stories\.(?:tsx|jsx|ts|js)$"),
    ("tailwind", r"(^|/)tailwind\.config\.(?:js|cjs|mjs|ts)$"),
    ("theme", r"(^|/)(?:theme|styles?|design-system)(/|[._-])"),
    ("component-library", r"(^|/)(?:ui|components|design-system)(/|$)"),
)

_CREATIVE_RULES: tuple[tuple[str, str], ...] = (
    ("canvas", r"(^|/)(?:canvas|whiteboard|scene|stage)(/|[._-])"),
    ("editor", r"(^|/)(?:editor|workspace|properties|inspector)(/|[._-])"),
    ("timeline", r"(^|/)(?:timeline|keyframes?|tracks?)(/|[._-])"),
    ("media-workspace", r"(^|/)(?:media|animation|video|audio)(/|[._-])"),
)

_WEB_ROUTE_SUFFIXES = {
    "aspx", "astro", "css", "cshtml", "ejs", "erb", "ftl", "handlebars",
    "hbs", "htm", "html", "jsx", "less", "liquid", "mdx",
    "mustache", "njk", "nunjucks", "pcss", "php", "pug", "razor",
    "sass", "scss", "svelte", "tsx", "twig", "vue",
}
_STRUCTURED_DESIGN_SUFFIXES = {"json", "toml", "yaml", "yml"}
_VISUAL_ASSET_SUFFIXES = {
    "avif", "gif", "icns", "ico", "jpeg", "jpg", "otf", "png", "svg",
    "svgz", "ttf", "webmanifest", "webp", "woff", "woff2",
}
_NATIVE_DECLARATIVE_SUFFIXES = {
    "axaml", "glade", "qml", "storyboard", "ui", "xaml", "xib",
}

_CONTENT_SOURCE_SUFFIXES: dict[str, frozenset[str]] = {
    "web": frozenset({
        "astro", "cjs", "cshtml", "ejs", "erb", "hbs", "htm", "html",
        "js", "jsx", "liquid", "mdx", "mjs", "mts", "mustache", "njk",
        "nunjucks", "php", "pug", "razor", "svelte", "ts", "tsx", "twig",
        "vue",
    }),
    "electron": frozenset({"cjs", "js", "jsx", "mjs", "mts", "ts", "tsx"}),
    "tauri": frozenset({"rs"}),
    "react-native": frozenset({"cjs", "js", "jsx", "mjs", "mts", "ts", "tsx"}),
    "flutter": frozenset({"dart", "yaml", "yml"}),
    "ios": frozenset({"h", "hpp", "m", "mm", "swift"}),
    "android": frozenset({"gradle", "java", "kt", "kts", "xml"}),
    "macos": frozenset({"h", "hpp", "m", "mm", "swift"}),
    "windows": frozenset({"axaml", "cs", "csproj", "xaml"}),
    "linux": frozenset({
        "c", "cc", "cpp", "glade", "h", "hpp", "py", "qml", "ui",
    }),
}


def _content_rule_applies(platform: str, path: str, suffix: str) -> bool:
    """Keep framework names in schemas, prompts, and backend data from becoming UI evidence."""
    if suffix in _CONTENT_SOURCE_SUFFIXES.get(platform, frozenset()):
        return True
    name = path.rsplit("/", 1)[-1].lower()
    if name == "package.json" and platform in {"web", "electron", "react-native"}:
        return True
    if name == "cargo.toml" and platform == "tauri":
        return True
    return name == "pubspec.yaml" and platform == "flutter"


def _web_route_is_ui_capable(path: str, suffix: str) -> bool:
    if suffix not in _WEB_ROUTE_SUFFIXES:
        return False
    if suffix == "php":
        return bool(
            re.search(
                r"(^|/)(?:pages|views|templates|components)(/|$)",
                path,
                re.IGNORECASE,
            )
        )
    return True


def _platform_path_is_ui_capable(
    platform: str,
    marker: str,
    path: str,
    suffix: str,
) -> bool:
    """Keep wrapper/platform directories as context, not UI authority by themselves."""
    if suffix in _VISUAL_ASSET_SUFFIXES:
        return True
    if suffix in _NATIVE_DECLARATIVE_SUFFIXES:
        return True
    if platform in {"webview", "electron"}:
        return _web_route_is_ui_capable(path, suffix)
    if platform == "react-native":
        return suffix in {"jsx", "tsx"}
    if platform == "android":
        return bool(
            re.search(
                r"(^|/)(?:[^/]+/)?src/main/res/"
                r"(?:layout|values[^/]*|drawable[^/]*|mipmap[^/]*|font)(/|$)",
                path,
                re.IGNORECASE,
            )
        )
    if marker == "windows-ui":
        return suffix in {"axaml", "xaml"}
    if platform == "linux":
        return suffix in {"glade", "qml", "ui"}
    return False


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def is_established_system_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(
        re.search(pattern, normalized, re.IGNORECASE)
        for _, pattern in _SYSTEM_RULES
    )


def established_system_evidence_paths(paths: Iterable[str]) -> list[str]:
    """Choose one deterministic tracked representative for each detected system marker."""
    normalized = sorted({str(path).replace("\\", "/") for path in paths})
    representatives: set[str] = set()
    for _, pattern in _SYSTEM_RULES:
        matches = [
            path for path in normalized if re.search(pattern, path, re.IGNORECASE)
        ]
        if matches:
            representatives.add(matches[0])
    return sorted(representatives)


def _document_matches(
    path: str, text: str
) -> tuple[dict[str, set[str]], set[str], set[str]]:
    """Classify one document while keeping native wrappers out of generic web."""
    platform_markers: dict[str, set[str]] = defaultdict(set)
    specific_platforms: set[str] = set()
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    for platform, marker, pattern in _PATH_RULES:
        if (
            platform != "web"
            and re.search(pattern, path, re.IGNORECASE)
            and _platform_path_is_ui_capable(platform, marker, path, suffix)
        ):
            platform_markers[platform].add(marker)
            specific_platforms.add(platform)
    for platform, marker, pattern in _CONTENT_RULES:
        if (
            platform != "web"
            and _content_rule_applies(platform, path, suffix)
            and re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        ):
            platform_markers[platform].add(marker)
            specific_platforms.add(platform)
    if suffix == "swift" and re.search(r"\bSwiftUI\b|\bView\s*\{", text):
        segments = {part.lower() for part in path.split("/")}
        if "ios" in segments and "macos" not in segments:
            swiftui_platforms = ("ios",)
        elif "macos" in segments and "ios" not in segments:
            swiftui_platforms = ("macos",)
        else:
            swiftui_platforms = ("ios", "macos")
        for platform in swiftui_platforms:
            platform_markers[platform].add("swiftui-cross-platform")
            specific_platforms.add(platform)
    if suffix == "cs" and re.search(r"\bclass\s+\w*Window\b", text):
        platform_markers["windows"].add("windows-class")
        specific_platforms.add("windows")
    if not specific_platforms:
        for platform, marker, pattern in _PATH_RULES:
            if (
                platform == "web"
                and re.search(pattern, path, re.IGNORECASE)
                and (marker != "web-route" or _web_route_is_ui_capable(path, suffix))
            ):
                platform_markers[platform].add(marker)
        for platform, marker, pattern in _CONTENT_RULES:
            if (
                platform == "web"
                and _content_rule_applies(platform, path, suffix)
                and re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            ):
                platform_markers[platform].add(marker)
        if suffix in {"js", "mjs", "cjs", "ts", "mts", "cts"} and re.search(
            r"(?:\breturn\s*|=>\s*)\(?\s*<[A-Za-z][A-Za-z0-9._:-]*(?:\s|/?>)",
            text,
        ):
            platform_markers["web"].add("jsx")
    system_markers = {
        marker
        for marker, pattern in _SYSTEM_RULES
        if re.search(pattern, path, re.IGNORECASE)
    }
    if not platform_markers:
        system_markers = {
            marker
            for marker in system_markers
            if marker in {"storybook", "tailwind"}
            or (
                marker in {"design-tokens", "theme"}
                and suffix in _STRUCTURED_DESIGN_SUFFIXES
            )
        }
    creative_kinds = {
        kind
        for kind, pattern in _CREATIVE_RULES
        if re.search(pattern, path, re.IGNORECASE)
    }
    if not platform_markers:
        creative_kinds.clear()
    return platform_markers, system_markers, creative_kinds


_CONTEXT_PLATFORM_IDS = {
    "webview", "react-native", "flutter", "electron", "tauri",
    "ios", "android", "macos", "windows", "linux",
}
_WEB_WRAPPER_CONTEXTS = {"webview", "react-native", "flutter", "electron", "tauri"}
_NATIVE_CONTEXTS = {"ios", "android", "macos", "windows", "linux"}
_ASSET_SUFFIXES = {
    "avif", "gif", "icns", "ico", "jpeg", "jpg", "otf", "png", "svg",
    "svgz", "ttf", "webmanifest", "webp", "woff", "woff2",
}


PLATFORM_MARKER_IDS = frozenset(
    {marker for _, marker, _ in _PATH_RULES}
    | {marker for _, marker, _ in _CONTENT_RULES}
    | {
        "jsx",
        "repository-context",
        "repository-context-asset",
        "swiftui-cross-platform",
        "windows-class",
    }
)


def _apply_repository_context(
    path: str,
    platform_markers: dict[str, set[str]],
    context_platforms: Iterable[str],
    system_markers: Iterable[str] = (),
) -> None:
    context = {
        str(item) for item in context_platforms if str(item) in _CONTEXT_PLATFORM_IDS
    }
    if "web" in platform_markers:
        for platform in context & _WEB_WRAPPER_CONTEXTS:
            platform_markers[platform].add("repository-context")
    if set(system_markers):
        # Shared tokens/themes belong to the enclosing runtime adapter even
        # when their structured data contains no framework syntax. Without a
        # wrapper/native context, v1's conservative default is the qualified
        # web adapter; non-web repositories contribute bounded context below.
        for platform in context or {"web"}:
            platform_markers[platform].add("repository-context")
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if (
        suffix == "swift"
        and len(context & {"ios", "macos"}) == 1
        and "swiftui-cross-platform"
        in platform_markers.get("ios", set()) | platform_markers.get("macos", set())
    ):
        selected = next(iter(context & {"ios", "macos"}))
        for platform in {"ios", "macos"} - {selected}:
            markers = platform_markers.get(platform)
            if markers is not None:
                markers.discard("swiftui-cross-platform")
                if not markers:
                    platform_markers.pop(platform, None)
    native_context = context & _NATIVE_CONTEXTS
    if suffix in _ASSET_SUFFIXES and native_context:
        for platform in native_context:
            platform_markers[platform].add("repository-context-asset")
        if re.search(
            r"(^|/)(?:Assets|Resources)(/|$)|(^|/)[^/]+/src/main/res/",
            path,
        ):
            platform_markers.pop("web", None)


def _contexts_for_document(
    path: str,
    global_context: set[str],
    context_by_path: Mapping[str, Iterable[str]] | None,
) -> set[str]:
    result = set(global_context)
    if context_by_path is not None:
        result.update(str(item) for item in context_by_path.get(path, ()))
    return result


def detect_product_ui(
    documents: Iterable[tuple[str, str]],
    *,
    candidate_file_count: int | None = None,
    inspection_truncated: bool = False,
    context_platforms: Iterable[str] = (),
    context_platforms_by_path: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Return deterministic path/marker evidence without returning source content."""
    platform_files: dict[str, set[str]] = defaultdict(set)
    markers: dict[str, set[str]] = defaultdict(set)
    system_files: dict[str, set[str]] = defaultdict(set)
    creative_files: dict[str, set[str]] = defaultdict(set)
    inspected: set[str] = set()
    repository_context = {
        str(item)
        for item in context_platforms
        if str(item) in _CONTEXT_PLATFORM_IDS
    }
    for raw_path, text in documents:
        path = raw_path.replace("\\", "/")
        inspected.add(path)
        document_platforms, document_systems, document_creative = _document_matches(path, text)
        _apply_repository_context(
            path,
            document_platforms,
            _contexts_for_document(
                path, repository_context, context_platforms_by_path
            ),
            document_systems,
        )
        for platform, document_markers in document_platforms.items():
            platform_files[platform].add(path)
            markers[platform].update(document_markers)
        for marker in document_systems:
            system_files[marker].add(path)
        for kind in document_creative:
            creative_files[kind].add(path)

    platforms = [
        {
            "id": platform,
            "matchedFiles": sorted(platform_files[platform])[:50],
            "markers": sorted(markers[platform])[:20],
        }
        for platform in ("web", "webview", "ios", "android", "react-native", "flutter", "electron", "tauri", "macos", "windows", "linux")
        if platform_files.get(platform)
    ]
    systems = [
        {"marker": marker, "matchedFiles": sorted(system_files[marker])[:50]}
        for marker, _ in _SYSTEM_RULES
        if system_files.get(marker)
    ]
    creative = [
        {"kind": kind, "matchedFiles": sorted(creative_files[kind])[:50]}
        for kind, _ in _CREATIVE_RULES
        if creative_files.get(kind)
    ]
    applicable = bool(platforms or systems or creative)
    if candidate_file_count is None:
        candidate_file_count = len(inspected)
    if (
        not isinstance(candidate_file_count, int)
        or isinstance(candidate_file_count, bool)
        or candidate_file_count < len(inspected)
        or candidate_file_count > 100_000
        or not isinstance(inspection_truncated, bool)
        or inspection_truncated is not (candidate_file_count > len(inspected))
    ):
        raise ValueError("Product Interface detection inspection metadata is inconsistent.")
    result = {
        "schemaVersion": "jstack.ui.detection.v1",
        "applicable": applicable,
        "inspectedFileCount": len(inspected),
        "candidateFileCount": candidate_file_count,
        "inspectionTruncated": inspection_truncated,
        "platforms": platforms,
        "establishedSystemHints": systems,
        "creativeSurfaceHints": creative,
        "defaultProfileSuggestion": "creative-canvas" if creative else "editorial-calm",
        "contentReturned": False,
    }
    result["detectionSha256"] = _digest(result)
    return result


def detect_product_ui_scope(
    documents: Iterable[tuple[str, str]],
    *,
    context_platforms: Iterable[str] = (),
    context_platforms_by_path: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Return the full bounded match set for internal authorization checks."""
    matched_paths: set[str] = set()
    platform_ids: set[str] = set()
    system_paths: set[str] = set()
    creative_kinds: set[str] = set()
    platforms_by_path: dict[str, set[str]] = defaultdict(set)
    inspected: set[str] = set()
    repository_context = {
        str(item)
        for item in context_platforms
        if str(item) in _CONTEXT_PLATFORM_IDS
    }
    for raw_path, text in documents:
        path = raw_path.replace("\\", "/")
        inspected.add(path)
        document_platforms, document_systems, document_creative = _document_matches(path, text)
        _apply_repository_context(
            path,
            document_platforms,
            _contexts_for_document(
                path, repository_context, context_platforms_by_path
            ),
            document_systems,
        )
        platform_ids.update(document_platforms)
        platforms_by_path[path].update(document_platforms)
        if document_systems:
            system_paths.add(path)
        creative_kinds.update(document_creative)
        matched = bool(document_platforms or document_systems or document_creative)
        if matched:
            matched_paths.add(path)
    result = {
        "schemaVersion": "jstack.ui.detection-scope.v1",
        "inspectedFileCount": len(inspected),
        "matchedPaths": sorted(matched_paths),
        "platforms": [item for item in (
            "web", "webview", "ios", "android", "react-native", "flutter",
            "electron", "tauri", "macos", "windows", "linux",
        ) if item in platform_ids],
        "pathPlatforms": [
            {
                "path": path,
                "platforms": [item for item in (
                    "web", "webview", "ios", "android", "react-native", "flutter",
                    "electron", "tauri", "macos", "windows", "linux",
                ) if item in platforms_by_path[path]],
            }
            for path in sorted(platforms_by_path)
            if platforms_by_path[path]
        ],
        "establishedSystemPaths": sorted(system_paths),
        "creativeSurfaceKinds": [item for item in (
            "canvas", "editor", "timeline", "media-workspace",
        ) if item in creative_kinds],
        "contentReturned": False,
    }
    result["scopeSha256"] = _digest(result)
    return result
