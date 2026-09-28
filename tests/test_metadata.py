import json

import pytest

from analyzer.jar import SafeJar
from analyzer.limits import Limits
from analyzer.metadata import (LOADER_FABRIC, LOADER_FORGE, LOADER_NEOFORGE,
                               LOADER_OTHER_JAVA, LOADER_OTHER_MC, LOADER_UNKNOWN,
                               MetadataError, detect_loader, parse_fabric,
                               parse_mcmod_info, parse_mods_toml,
                               parse_neoforge_toml, parse_plugin_yml,
                               parse_quilt, parse_simple_yaml, read_metadata)
from analyzer.models import ManifestInfo

FABRIC_JSON = json.dumps({
    "schemaVersion": 1,
    "id": "examplemod",
    "version": "1.2.0",
    "name": "Example Mod",
    "description": "An example.",
    "authors": ["Alice", {"name": "Bob"}],
    "entrypoints": {"main": ["com.example.Main"], "client": [{"value": "com.example.Client"}]},
    "mixins": ["example.mixins.json"],
    "depends": {"fabricloader": ">=0.15.0", "minecraft": "~1.20.1", "fabric-api": ["*"]},
})

FORGE_TOML = '''
modLoader="javafml"
loaderVersion="[47,)"
license="MIT"
[[mods]]
modId="examplemod"
version="${file.jarVersion}"
displayName="Example Mod"
authors="Alice"
description=\'\'\'Multi
line\'\'\'
[[dependencies.examplemod]]
modId="forge"
mandatory=true
versionRange="[47,)"
[[dependencies.examplemod]]
modId="minecraft"
mandatory=true
versionRange="[1.20.1,1.21)"
'''

NEOFORGE_TOML = '''
modLoader="javafml"
loaderVersion="[1,)"
[[mods]]
modId="neomod"
version="2.0.0"
displayName="Neo Mod"
[[dependencies.neomod]]
modId="neoforge"
type="required"
versionRange="[20.5,)"
[[dependencies.neomod]]
modId="jei"
type="optional"
versionRange="*"
'''


def test_fabric():
    [mod] = parse_fabric(FABRIC_JSON)
    assert mod.loader == LOADER_FABRIC
    assert (mod.mod_id, mod.name, mod.version) == ("examplemod", "Example Mod", "1.2.0")
    assert mod.authors == ["Alice", "Bob"]
    assert mod.minecraft_version == "~1.20.1"
    assert mod.loader_version == ">=0.15.0"
    assert "com.example.Client" in mod.extra["entrypoints"]
    assert mod.extra["mixins"] == "example.mixins.json"


def test_quilt():
    text = json.dumps({"schema_version": 1, "quilt_loader": {
        "group": "com.example", "id": "qmod", "version": "0.1.0",
        "metadata": {"name": "Q Mod", "contributors": {"Carol": "Owner"}},
        "depends": ["minecraft", {"id": "quilt_loader", "versions": ">=0.19"}]}})
    [mod] = parse_quilt(text)
    assert (mod.mod_id, mod.name, mod.authors) == ("qmod", "Q Mod", ["Carol"])
    assert mod.loader_version == ">=0.19"


def test_forge_toml():
    [mod] = parse_mods_toml(FORGE_TOML)
    assert mod.loader == LOADER_FORGE
    assert mod.mod_id == "examplemod"
    assert mod.minecraft_version == "[1.20.1,1.21)"
    assert mod.loader_version == "[47,)"
    assert mod.description == "Multi\nline"


def test_neoforge_toml_new_filename():
    [mod] = parse_neoforge_toml(NEOFORGE_TOML)
    assert mod.loader == LOADER_NEOFORGE
    assert mod.dependencies["jei"] == "* (optional)"
    assert mod.loader_version == "[20.5,)"


def test_neoforge_in_legacy_mods_toml_detected_by_dependency():
    [mod] = parse_mods_toml(NEOFORGE_TOML)
    assert mod.loader == LOADER_NEOFORGE


def test_mcmod_info_both_layouts():
    entry = {"modid": "old", "name": "Old Mod", "version": "1.0", "mcversion": "1.12.2", "authorList": ["Dan"]}
    [a] = parse_mcmod_info(json.dumps([entry]))
    [b] = parse_mcmod_info(json.dumps({"modListVersion": 2, "modList": [entry]}))
    assert a.mod_id == b.mod_id == "old"
    assert a.minecraft_version == "1.12.2"


def test_plugin_yml():
    text = """# comment
name: CoolPlugin
version: '1.4'
main: com.cool.Plugin
api-version: "1.20"
authors: [Eve, "Frank"]
depend:
  - Vault
softdepend: [PlaceholderAPI]
description: |
  Line one
  Line two
commands:
  cool:
    description: nested, ignored
"""
    [mod] = parse_plugin_yml(text)
    assert (mod.name, mod.version, mod.extra["main"]) == ("CoolPlugin", "1.4", "com.cool.Plugin")
    assert mod.authors == ["Eve", "Frank"]
    assert mod.dependencies == {"Vault": "*", "PlaceholderAPI": "* (optional)"}
    assert mod.description == "Line one\nLine two"


@pytest.mark.parametrize("parser,text", [
    (parse_fabric, "{not json"),
    (parse_fabric, "[1, 2, 3]"),
    # deeply nested; explicit id keeps the 200k-char string out of the node ID
    # (Windows caps env vars like PYTEST_CURRENT_TEST at 32767 chars)
    pytest.param(parse_fabric, "[" * 100_000 + "]" * 100_000, id="fabric-deeply-nested"),
    (parse_quilt, "{}"),
    (parse_mods_toml, "this is = = not toml"),
    (parse_mods_toml, 'modLoader="javafml"'),
    (parse_mcmod_info, '"just a string"'),
    (parse_plugin_yml, "nothing: useful"),
])
def test_malformed_metadata_raises_metadata_error(parser, text):
    with pytest.raises(MetadataError):
        parser(text)


def test_wrong_types_are_ignored_not_crashing():
    text = json.dumps({"id": 123, "name": ["list"], "version": {"a": 1}, "authors": 42,
                       "depends": "minecraft", "entrypoints": [1, 2], "mixins": {"x": 1}})
    [mod] = parse_fabric(text)
    assert mod.mod_id == "123"
    assert mod.name is None and mod.version is None
    assert mod.authors == [] and mod.dependencies == {}


def test_read_metadata_from_jar_with_placeholder(make_jar):
    path = make_jar({
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Version: 3.1.4\n",
        "META-INF/mods.toml": FORGE_TOML,
        "fabric.mod.json": "{broken",
    })
    manifest = ManifestInfo(present=True, attributes={"Implementation-Version": "3.1.4"})
    with SafeJar.open(path) as jar:
        mods, errors = read_metadata(jar, manifest)
    assert [m.version for m in mods] == ["3.1.4"]
    assert len(errors) == 1 and errors[0].startswith("fabric.mod.json")


def test_oversized_metadata_reported(make_jar):
    path = make_jar({"fabric.mod.json": FABRIC_JSON})
    with SafeJar.open(path, Limits(max_metadata_size=50)) as jar:
        mods, errors = read_metadata(jar, ManifestInfo())
    assert mods == [] and "limit" in errors[0]


def test_invalid_utf8_metadata(make_jar):
    path = make_jar({"fabric.mod.json": b'{"id": "bad\xff\xfe", "version": "1"}'})
    with SafeJar.open(path) as jar:
        mods, errors = read_metadata(jar, ManifestInfo())
    assert mods[0].mod_id.startswith("bad") and errors == []


def test_detect_loader():
    [fab] = parse_fabric(FABRIC_JSON)
    [forge] = parse_mods_toml(FORGE_TOML)
    empty = ManifestInfo()
    assert detect_loader([fab], empty, True, True)[0] == LOADER_FABRIC
    assert detect_loader([fab, forge], empty, True, True)[0] == "Multi-loader (Fabric, Forge)"
    assert detect_loader([], ManifestInfo(attributes={"FMLCorePlugin": "x"}), True, True)[0] == LOADER_FORGE
    assert detect_loader([], empty, True, True)[0] == LOADER_OTHER_MC
    assert detect_loader([], empty, True, False)[0] == LOADER_OTHER_JAVA
    assert detect_loader([], empty, False, False)[0] == LOADER_UNKNOWN


def test_simple_yaml_ignores_nested():
    assert parse_simple_yaml("a: 1\nb:\n  c: 2\n") == {"a": "1", "b": []}
