from analyzer.version import APP_NAME, VERSION


def test_version_info():
    assert APP_NAME == "Minecraft JAR Analyzer"
    assert VERSION == "0.1.0"
