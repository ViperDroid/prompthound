from prompthound.scanner import scan_path


def _ids(path):
    return {f["rule"]["id"] for f in scan_path(str(path))}


def test_detects_hardcoded_key(tmp_path):
    # Build the fake key from fragments so no literal secret is committed to source.
    fake_key = "sk-" + "fake" + "examplekey" * 3 + "0123456789"
    (tmp_path / "a.py").write_text('openai.api_key = "%s"\n' % fake_key)
    assert "PH001" in _ids(tmp_path)


def test_detects_eval(tmp_path):
    (tmp_path / "b.py").write_text("eval(answer)\n")
    assert "PH002" in _ids(tmp_path)


def test_detects_innerhtml_js(tmp_path):
    (tmp_path / "c.js").write_text("el.innerHTML = answer;\n")
    assert "PH006" in _ids(tmp_path)


def test_clean_file_has_no_findings(tmp_path):
    (tmp_path / "d.py").write_text("x = 1 + 1\nprint('hello world')\n")
    assert scan_path(str(tmp_path)) == []


def test_skips_unknown_extensions(tmp_path):
    (tmp_path / "notes.txt").write_text("eval(answer) sk-xxxx\n")
    assert scan_path(str(tmp_path)) == []
