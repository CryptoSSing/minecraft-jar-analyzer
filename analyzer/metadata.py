"""Read Minecraft mod / plugin descriptor files and work out the mod loader.

Supported descriptors:

  fabric.mod.json               Fabric (JSON)
  quilt.mod.json                Quilt (JSON)
  META-INF/mods.toml            Forge 1.13+ (TOML), also NeoForge before 1.20.5
  META-INF/neoforge.mods.toml   NeoForge 1.20.5+ (TOML)
  mcmod.info                    Legacy Forge 1.12 and older (JSON)
  plugin.yml / paper-plugin.yml Bukkit / Spigot / Paper server plugins (YAML)

Metadata is written by whoever built the JAR, so it is *claims*, not facts:
a malicious JAR can say it is "Sodium by JellySquid". We record the claims so
the indicator rules can check them for inconsistencies and impersonation.

Missing metadata is NOT suspicious by itself - plenty of legitimate libraries
have none.
"""

from __future__ import annotations

import json
import tomllib

from .jar import EntryReadError, SafeJar
from .models import ManifestInfo, ModInfo
from .sanitize import safe_text

LOADER_FABRIC = "Fabric"
LOADER_QUILT = "Quilt"
LOADER_FORGE = "Forge"
LOADER_NEOFORGE = "NeoForge"
LOADER_BUKKIT = "Bukkit/Paper plugin"
LOADER_OTHER_MC = "Other Java/Minecraft"
LOADER_OTHER_JAVA = "Other Java"
LOADER_UNKNOWN = "Unknown"

MAX_LIST_ITEMS = 100


class MetadataError(ValueError):
    """A descriptor file exists but could not be parsed."""


# ---------------------------------------------------------------------------
# Defensive helpers: turn "whatever the JSON contained" into the type we want.
# ---------------------------------------------------------------------------

def _as_str(value: object, max_length: int = 500) -> str | None:
    """Return a safe string for str/number values, None for anything else."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (str, int, float)):
        return safe_text(str(value), max_length=max_length)
    return None


def _as_text_block(value: object) -> str | None:
    """Like _as_str but keeps newlines (descriptions)."""
    if isinstance(value, str):
        return safe_text(value.strip(), max_length=2000, allow_newlines=True)
    return None


def _people(value: object) -> list[str]:
    """Authors can be "Name", ["A", "B"], [{"name": "A"}], or {"A": "Owner"} (Quilt)."""
    if isinstance(value, str):
        return [safe_text(value, 200)]
    names: list[str] = []
    if isinstance(value, list):
        for item in value[:MAX_LIST_ITEMS]:
            if isinstance(item, dict):
                item = item.get("name")
            if (s := _as_str(item, 200)) is not None:
                names.append(s)
    elif isinstance(value, dict):  # Quilt: {"Person": "Role"}
        names = [safe_text(k, 200) for k in list(value)[:MAX_LIST_ITEMS]]
    return names


def _str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [safe_text(value, 300)]
    if isinstance(value, list):
        return [s for v in value[:MAX_LIST_ITEMS] if (s := _as_str(v, 300)) is not None]
    return []


def _decode(data: bytes) -> str:
    # "utf-8-sig" also strips a byte-order mark that some editors add.
    return data.decode("utf-8-sig", errors="replace")


def _load_json(text: str) -> object:
    try:
        return json.loads(text)
    except RecursionError:  # e.g. [[[[[[...]]]]]] nested 100,000 levels deep
        raise MetadataError("JSON is nested too deeply") from None
    except json.JSONDecodeError as exc:
        raise MetadataError(f"invalid JSON: {exc}") from None


def _load_toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except RecursionError:
        raise MetadataError("TOML is nested too deeply") from None
    except tomllib.TOMLDecodeError as exc:
        raise MetadataError(f"invalid TOML: {exc}") from None


# ---------------------------------------------------------------------------
# Fabric
# ---------------------------------------------------------------------------

def _fabric_deps(value: object) -> dict[str, str]:
    """Fabric "depends": {"minecraft": "~1.20.1", "fabric-api": ["*"]}"""
    deps: dict[str, str] = {}
    if isinstance(value, dict):
        for key, ver in list(value.items())[:MAX_LIST_ITEMS]:
            versions = _str_list(ver)
            deps[safe_text(key, 200)] = " || ".join(versions) if versions else "*"
    return deps


def _entrypoint_classes(value: object) -> list[str]:
    """Fabric/Quilt entrypoints: {"main": ["a.B", {"value": "c.D"}], ...}"""
    classes: list[str] = []
    if isinstance(value, dict):
        for items in value.values():
            items = items if isinstance(items, list) else [items]
            for item in items[:MAX_LIST_ITEMS]:
                if isinstance(item, dict):
                    item = item.get("value")
                if (s := _as_str(item, 300)) is not None:
                    classes.append(s)
    return classes[:MAX_LIST_ITEMS]


def parse_fabric(text: str, source: str = "fabric.mod.json") -> list[ModInfo]:
    data = _load_json(text)
    if not isinstance(data, dict):
        raise MetadataError("top level is not a JSON object")
    deps = _fabric_deps(data.get("depends"))
    mod = ModInfo(
        loader=LOADER_FABRIC,
        source_file=source,
        mod_id=_as_str(data.get("id")),
        name=_as_str(data.get("name")),
        version=_as_str(data.get("version")),
        description=_as_text_block(data.get("description")),
        authors=_people(data.get("authors")),
        dependencies=deps,
        minecraft_version=deps.get("minecraft"),
        loader_version=deps.get("fabricloader"),
    )
    entrypoints = _entrypoint_classes(data.get("entrypoints"))
    if entrypoints:
        mod.extra["entrypoints"] = ", ".join(entrypoints)
    mixins = [m.get("config") if isinstance(m, dict) else m for m in data.get("mixins", [])
              ] if isinstance(data.get("mixins"), list) else []
    if mixins := _str_list(mixins):
        mod.extra["mixins"] = ", ".join(mixins)
    if env := _as_str(data.get("environment")):
        mod.extra["environment"] = env
    return [mod]


# ---------------------------------------------------------------------------
# Quilt
# ---------------------------------------------------------------------------

def _quilt_deps(value: object) -> dict[str, str]:
    """Quilt "depends": ["minecraft", {"id": "quilt_loader", "versions": ">=0.19"}]"""
    deps: dict[str, str] = {}
    if isinstance(value, list):
        for item in value[:MAX_LIST_ITEMS]:
            if isinstance(item, str):
                deps[safe_text(item, 200)] = "*"
            elif isinstance(item, dict) and (dep_id := _as_str(item.get("id"), 200)):
                versions = item.get("versions")
                if isinstance(versions, dict):  # {"any": [...]} / {"all": [...]}
                    versions = next(iter(versions.values()), "*")
                deps[dep_id] = " || ".join(_str_list(versions)) or "*"
    return deps


def parse_quilt(text: str, source: str = "quilt.mod.json") -> list[ModInfo]:
    data = _load_json(text)
    if not isinstance(data, dict) or not isinstance(data.get("quilt_loader"), dict):
        raise MetadataError("missing 'quilt_loader' object")
    ql = data["quilt_loader"]
    meta = ql.get("metadata") if isinstance(ql.get("metadata"), dict) else {}
    deps = _quilt_deps(ql.get("depends"))
    mod = ModInfo(
        loader=LOADER_QUILT,
        source_file=source,
        mod_id=_as_str(ql.get("id")),
        name=_as_str(meta.get("name")),
        version=_as_str(ql.get("version")),
        description=_as_text_block(meta.get("description")),
        authors=_people(meta.get("contributors")),
        dependencies=deps,
        minecraft_version=deps.get("minecraft"),
        loader_version=deps.get("quilt_loader"),
    )
    if group := _as_str(ql.get("group")):
        mod.extra["group"] = group
    if entrypoints := _entrypoint_classes(ql.get("entrypoints")):
        mod.extra["entrypoints"] = ", ".join(entrypoints)
    return [mod]


# ---------------------------------------------------------------------------
# Forge / NeoForge (mods.toml)
# ---------------------------------------------------------------------------

def parse_mods_toml(text: str, source: str = "META-INF/mods.toml",
                    force_loader: str | None = None) -> list[ModInfo]:
    """Parse a Forge-style mods.toml. One file can describe several mods.

    Old NeoForge versions also used META-INF/mods.toml, so unless the loader is
    forced we decide per mod: depending on "neoforge" means NeoForge.
    """
    data = _load_toml(text)
    mods_table = data.get("mods")
    if not isinstance(mods_table, list) or not mods_table:
        raise MetadataError("no [[mods]] entries found")
    all_deps = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
    top_loader_version = _as_str(data.get("loaderVersion"))

    results = []
    for entry in mods_table[:MAX_LIST_ITEMS]:
        if not isinstance(entry, dict):
            continue
        mod_id = _as_str(entry.get("modId"))
        deps: dict[str, str] = {}
        dep_list = all_deps.get(mod_id, []) if mod_id else []
        for dep in dep_list[:MAX_LIST_ITEMS] if isinstance(dep_list, list) else []:
            if not isinstance(dep, dict) or not (dep_id := _as_str(dep.get("modId"), 200)):
                continue
            version_range = _as_str(dep.get("versionRange"), 200) or "*"
            # Forge uses mandatory=true/false; NeoForge uses type="required"/"optional"/...
            dep_type = _as_str(dep.get("type"), 50)
            optional = dep.get("mandatory") is False or (dep_type is not None and dep_type.lower() != "required")
            deps[dep_id] = f"{version_range} (optional)" if optional else version_range

        if force_loader:
            loader = force_loader
        else:
            loader = LOADER_NEOFORGE if "neoforge" in deps else LOADER_FORGE
        loader_dep = deps.get("neoforge") or deps.get("forge")
        mod = ModInfo(
            loader=loader,
            source_file=source,
            mod_id=mod_id,
            name=_as_str(entry.get("displayName")),
            version=_as_str(entry.get("version")),
            description=_as_text_block(entry.get("description")),
            authors=_people(entry.get("authors")),
            dependencies=deps,
            minecraft_version=deps.get("minecraft"),
            loader_version=loader_dep or top_loader_version,
        )
        if (lic := _as_str(data.get("license"))) is not None:
            mod.extra["license"] = lic
        results.append(mod)
    if not results:
        raise MetadataError("no valid [[mods]] entries found")
    return results


def parse_neoforge_toml(text: str, source: str = "META-INF/neoforge.mods.toml") -> list[ModInfo]:
    return parse_mods_toml(text, source, force_loader=LOADER_NEOFORGE)


# ---------------------------------------------------------------------------
# Legacy Forge (mcmod.info)
# ---------------------------------------------------------------------------

def parse_mcmod_info(text: str, source: str = "mcmod.info") -> list[ModInfo]:
    data = _load_json(text)
    # Two historical layouts: a plain list, or {"modListVersion": 2, "modList": [...]}.
    if isinstance(data, dict):
        data = data.get("modList")
    if not isinstance(data, list):
        raise MetadataError("expected a list of mods")
    results = []
    for entry in data[:MAX_LIST_ITEMS]:
        if not isinstance(entry, dict):
            continue
        deps = {d: "*" for d in _str_list(entry.get("requiredMods") or entry.get("dependencies"))}
        mc = _as_str(entry.get("mcversion"))
        results.append(ModInfo(
            loader=LOADER_FORGE,
            source_file=source,
            mod_id=_as_str(entry.get("modid")),
            name=_as_str(entry.get("name")),
            version=_as_str(entry.get("version")),
            description=_as_text_block(entry.get("description")),
            authors=_people(entry.get("authorList") or entry.get("authors")),
            dependencies=deps,
            minecraft_version=mc,
            extra={"format": "legacy mcmod.info"},
        ))
    if not results:
        raise MetadataError("no mod entries found")
    return results


# ---------------------------------------------------------------------------
# Bukkit / Spigot / Paper (plugin.yml)
# ---------------------------------------------------------------------------

def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def parse_simple_yaml(text: str) -> dict[str, str | list[str]]:
    """Read only the top-level `key: value` pairs of a YAML file.

    Full YAML is complicated and would need the third-party PyYAML package.
    plugin.yml only needs a handful of top-level keys, so this tiny reader
    handles exactly these forms and ignores everything else (e.g. nested
    `commands:` blocks):

        name: MyPlugin            -> "MyPlugin"
        depend: [Vault, "Foo"]    -> ["Vault", "Foo"]
        authors:                  -> ["A", "B"]
          - A
          - B
        description: |            -> "line one\\nline two"
          line one
          line two
    """
    result: dict[str, str | list[str]] = {}
    list_key: str | None = None
    block_key: str | None = None
    for raw in text.splitlines():
        if raw.lstrip().startswith("#") or not raw.strip():
            continue
        if raw[0] in " \t-":  # indented (or list item) line
            stripped = raw.strip()
            if block_key is not None:
                existing = result[block_key]
                result[block_key] = f"{existing}\n{stripped}" if existing else stripped
            elif list_key is not None and stripped.startswith("-"):
                result[list_key].append(_unquote(stripped[1:].strip()))  # type: ignore[union-attr]
            continue
        list_key = block_key = None
        key, sep, value = raw.partition(":")
        if not sep:
            continue
        key = key.strip()
        value = value.split(" #", 1)[0].strip()
        if value == "":
            result[key] = []
            list_key = key
        elif value in ("|", ">", "|-", ">-", "|+", ">+"):
            result[key] = ""
            block_key = key
        elif value.startswith("[") and value.endswith("]"):
            result[key] = [_unquote(v.strip()) for v in value[1:-1].split(",") if v.strip()]
        else:
            result[key] = _unquote(value)
    return result


def parse_plugin_yml(text: str, source: str = "plugin.yml") -> list[ModInfo]:
    data = parse_simple_yaml(text)
    name = data.get("name")
    main = data.get("main")
    if not isinstance(name, str) and not isinstance(main, str):
        raise MetadataError("no 'name' or 'main' key found")
    authors = _people(data.get("authors")) + _people(data.get("author"))
    deps = {d: "*" for d in _str_list(data.get("depend"))}
    deps.update({d: "* (optional)" for d in _str_list(data.get("softdepend"))})
    mod = ModInfo(
        loader=LOADER_BUKKIT,
        source_file=source,
        mod_id=_as_str(name),
        name=_as_str(name),
        version=_as_str(data.get("version")),
        description=_as_text_block(data.get("description")),
        authors=authors,
        dependencies=deps,
        minecraft_version=_as_str(data.get("api-version")),
    )
    if isinstance(main, str):
        mod.extra["main"] = safe_text(main, 300)
    if isinstance(website := data.get("website"), str):
        mod.extra["website"] = safe_text(website, 300)
    return [mod]


# ---------------------------------------------------------------------------
# Reading all descriptors from a JAR
# ---------------------------------------------------------------------------

DESCRIPTORS = [
    ("fabric.mod.json", parse_fabric),
    ("quilt.mod.json", parse_quilt),
    ("META-INF/mods.toml", parse_mods_toml),
    ("META-INF/neoforge.mods.toml", parse_neoforge_toml),
    ("mcmod.info", parse_mcmod_info),
    ("plugin.yml", parse_plugin_yml),
    ("paper-plugin.yml", parse_plugin_yml),
]


def _resolve_placeholders(mod: ModInfo, manifest: ManifestInfo) -> None:
    """Forge mods often say version="${file.jarVersion}", meaning "use the
    Implementation-Version from the manifest". Substitute it for display."""
    if mod.version and "${file.jarVersion}" in mod.version:
        jar_version = manifest.attributes.get("Implementation-Version")
        if jar_version:
            mod.version = jar_version
            mod.extra["version_source"] = "MANIFEST.MF Implementation-Version"


def read_metadata(jar: SafeJar, manifest: ManifestInfo) -> tuple[list[ModInfo], list[str]]:
    """Parse every known descriptor in the JAR. Returns (mods, errors)."""
    mods: list[ModInfo] = []
    errors: list[str] = []
    for filename, parser in DESCRIPTORS:
        if not jar.has(filename):
            continue
        try:
            text = _decode(jar.read(filename, max_bytes=jar.limits.max_metadata_size))
            parsed = parser(text, filename)
        except (EntryReadError, MetadataError) as exc:
            errors.append(f"{filename}: {exc}")
            continue
        for mod in parsed:
            _resolve_placeholders(mod, manifest)
        mods.extend(parsed)
    return mods, errors


def detect_loader(mods: list[ModInfo], manifest: ManifestInfo, has_classes: bool,
                  references_minecraft: bool) -> tuple[str, list[str]]:
    """Decide which loader the JAR targets. Returns (loader, evidence list)."""
    evidence: list[str] = []
    loaders: list[str] = []
    for mod in mods:
        if mod.nested_in is None:
            evidence.append(f"{mod.source_file} found ({mod.loader})")
            if mod.loader not in loaders:
                loaders.append(mod.loader)

    if len(loaders) == 1:
        return loaders[0], evidence
    if len(loaders) > 1:
        return "Multi-loader (" + ", ".join(loaders) + ")", evidence

    if "FMLCorePlugin" in manifest.attributes:
        evidence.append("MANIFEST.MF declares FMLCorePlugin (legacy Forge coremod)")
        return LOADER_FORGE, evidence
    if references_minecraft:
        evidence.append("No mod descriptor, but classes reference Minecraft code")
        return LOADER_OTHER_MC, evidence
    if has_classes:
        evidence.append("No mod descriptor; contains Java classes")
        return LOADER_OTHER_JAVA, evidence
    evidence.append("No mod descriptor and no Java classes")
    return LOADER_UNKNOWN, evidence
