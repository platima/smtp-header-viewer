"""
Tests for decode-spam-headers.py.

Run with: python -m pytest tests/ -v
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

# Ensure the project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = PROJECT_ROOT / 'decode-spam-headers.py'
FIXTURES = PROJECT_ROOT / 'tests' / 'fixtures'
SAMPLE_EML = FIXTURES / 'sample.eml'


class TestCLIMode:
    """Tests for the script running in CLI mode (no DECODE_SPAM_HEADERS_WEB)."""

    def _run_script(self, args, env_extra=None):
        env = os.environ.copy()
        env.pop('DECODE_SPAM_HEADERS_WEB', None)
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, str(SCRIPT)] + args,
            capture_output=True, text=True, env=env, timeout=60
        )
        return result

    def test_help_flag(self):
        result = self._run_script(['--help'])
        assert result.returncode == 0
        assert 'usage' in result.stdout.lower() or 'decode' in result.stdout.lower()

    def test_analyse_sample_eml_text(self):
        result = self._run_script([str(SAMPLE_EML)])
        assert result.returncode == 0
        assert 'Test:' in result.stdout
        assert 'Received' in result.stdout

    def test_analyse_sample_eml_html(self):
        result = self._run_script(['-f', 'html', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert '<html' in result.stdout.lower()
        assert '<body' in result.stdout.lower()

    def test_analyse_with_no_resolve(self):
        result = self._run_script(['-R', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert 'Test:' in result.stdout

    def test_analyse_with_output_file(self):
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            outpath = f.name
        try:
            result = self._run_script(['-f', 'html', '-o', outpath, str(SAMPLE_EML)])
            assert result.returncode == 0
            content = Path(outpath).read_text(encoding='utf-8', errors='replace')
            assert '<html' in content.lower()
        finally:
            os.unlink(outpath)


class TestWebMode:
    """Tests for the script running in web mode (DECODE_SPAM_HEADERS_WEB=1)."""

    def _run_script(self, args):
        env = os.environ.copy()
        env['DECODE_SPAM_HEADERS_WEB'] = '1'
        result = subprocess.run(
            [sys.executable, str(SCRIPT)] + args,
            capture_output=True, text=True, env=env, timeout=60
        )
        return result

    def test_web_mode_html_output(self):
        result = self._run_script(['-f', 'html', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert '<html' in result.stdout.lower()

    def test_web_mode_has_toc(self):
        result = self._run_script(['-f', 'html', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert 'id="toc"' in result.stdout

    def test_cli_mode_no_toc(self):
        env = os.environ.copy()
        env.pop('DECODE_SPAM_HEADERS_WEB', None)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '-f', 'html', str(SAMPLE_EML)],
            capture_output=True, text=True, env=env, timeout=60
        )
        assert result.returncode == 0
        assert 'id="toc"' not in result.stdout

    def test_web_mode_text_output(self):
        result = self._run_script([str(SAMPLE_EML)])
        assert result.returncode == 0
        assert 'Test:' in result.stdout

    def test_forefront_header_parsed(self):
        result = self._run_script([str(SAMPLE_EML)])
        assert result.returncode == 0
        assert 'Forefront' in result.stdout or 'forefront' in result.stdout.lower()

    def test_spamassassin_header_parsed(self):
        result = self._run_script([str(SAMPLE_EML)])
        assert result.returncode == 0
        assert 'Spam' in result.stdout


class TestImportStubs:
    """Test that import stubs work correctly in web mode."""

    def test_stubs_dont_crash(self):
        """Script should not crash even if optional deps are missing (web mode)."""
        env = os.environ.copy()
        env['DECODE_SPAM_HEADERS_WEB'] = '1'
        # We can't easily remove installed packages, but we can verify
        # the script runs successfully with the env var set
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '-R', str(SAMPLE_EML)],
            capture_output=True, text=True, env=env, timeout=60
        )
        assert result.returncode == 0


class TestColourProcessing:
    """Test the replaceColors / htmlColors fix for nested markers."""

    def test_html_output_no_dangling_font_tags(self):
        env = os.environ.copy()
        env['DECODE_SPAM_HEADERS_WEB'] = '1'
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '-f', 'html', str(SAMPLE_EML)],
            capture_output=True, text=True, env=env, timeout=60
        )
        assert result.returncode == 0
        # Check for unmatched/dangling font close tags
        output = result.stdout
        open_count = output.count('<font ')
        close_count = output.count('</font>')
        # Allow some tolerance but they should be roughly equal
        assert abs(open_count - close_count) <= 2, \
            f'Mismatched font tags: {open_count} opens vs {close_count} closes'

    def test_no_escaped_font_tags_in_output(self):
        env = os.environ.copy()
        env['DECODE_SPAM_HEADERS_WEB'] = '1'
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '-f', 'html', str(SAMPLE_EML)],
            capture_output=True, text=True, env=env, timeout=60
        )
        assert result.returncode == 0
        # Escaped font tags indicate the htmlColors double-escape bug
        assert '&lt;font' not in result.stdout
        assert '&lt;/font&gt;' not in result.stdout


class TestSecurityInputHandling:
    """Test that potentially malicious input is handled safely."""

    def test_xss_in_headers(self):
        """Script should escape or safely handle XSS payloads in headers."""
        malicious = (
            'From: <script>alert("xss")</script>@evil.com\n'
            'To: victim@example.com\n'
            'Subject: <img onerror=alert(1) src=x>\n'
            'Received: from evil.com (evil.com [1.2.3.4])\n'
            '        by mx.example.com; Mon, 10 Jan 2022 12:00:00 +0000\n'
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(malicious)
            tmppath = f.name
        try:
            env = os.environ.copy()
            env['DECODE_SPAM_HEADERS_WEB'] = '1'
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '-f', 'html', '-R', tmppath],
                capture_output=True, text=True, env=env, timeout=60
            )
            # Script should not crash
            assert result.returncode == 0
            # Raw <script> tags should not appear unescaped in HTML output
            output = result.stdout
            assert '<script>alert' not in output
        finally:
            os.unlink(tmppath)

    def test_oversized_header_value(self):
        """Script should handle extremely long header values without crashing."""
        huge = 'X-Custom-Header: ' + 'A' * 100000 + '\n'
        normal = (
            'From: sender@example.com\n'
            'To: recipient@example.com\n'
            'Received: from mx.example.com (mx.example.com [1.2.3.4])\n'
            '        by mx2.example.com; Mon, 10 Jan 2022 12:00:00 +0000\n'
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(huge + normal)
            tmppath = f.name
        try:
            env = os.environ.copy()
            env['DECODE_SPAM_HEADERS_WEB'] = '1'
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '-R', tmppath],
                capture_output=True, text=True, env=env, timeout=120
            )
            assert result.returncode == 0
        finally:
            os.unlink(tmppath)


class TestWebModeOutputClean:
    """Regression tests for artefacts that must not appear in web-mode output."""

    def _run_web(self, args):
        env = os.environ.copy()
        env['DECODE_SPAM_HEADERS_WEB'] = '1'
        return subprocess.run(
            [sys.executable, str(SCRIPT)] + args,
            capture_output=True, text=True, env=env, timeout=60
        )

    def test_no_ansi_codes_in_stderr(self):
        """Logger must not emit ANSI escape sequences to stderr in web mode."""
        result = self._run_web(['-f', 'html', '-R', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert '\x1b[' not in result.stderr, \
            f'ANSI escape sequences found in stderr:\n{result.stderr[:500]}'

    def test_no_ansi_codes_in_stdout(self):
        """ANSI escape sequences must not bleed into the HTML stdout."""
        result = self._run_web(['-f', 'html', '-R', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert '\x1b[' not in result.stdout, \
            'ANSI escape sequences found in stdout (would appear as raw codes in browser)'

    def test_no_stray_font_close_tags(self):
        """Nested colour markers must not produce stray </font> text nodes."""
        result = self._run_web(['-f', 'html', '-R', str(SAMPLE_EML)])
        assert result.returncode == 0
        # If the depth-tracking fix is correct, open and close counts must match exactly.
        open_count  = result.stdout.count('<font ')
        close_count = result.stdout.count('</font>')
        assert open_count == close_count, \
            f'Mismatched <font> tags: {open_count} opens vs {close_count} closes'

    def test_no_escaped_font_close_in_rendered_text(self):
        """html.escape() must not be applied to </font> tags, which would
        render them as literal text in the browser."""
        result = self._run_web(['-f', 'html', '-R', str(SAMPLE_EML)])
        assert result.returncode == 0
        assert '&lt;/font&gt;' not in result.stdout, \
            'Escaped </font> found – nested colour processing bug is present'
        assert '&lt;font ' not in result.stdout, \
            'Escaped <font found – nested colour processing bug is present'

    def test_htmlcolors_nested_markers_unit(self):
        """Unit test: htmlColors() with explicitly nested colour markers."""
        import importlib.util, types
        # Load the module without executing main()
        spec = importlib.util.spec_from_file_location('dsh', str(SCRIPT))
        mod  = importlib.util.load_from_spec = None  # not used directly

        # Import via exec to get Logger without running main
        ns = {'__name__': '__test__', '__file__': str(SCRIPT)}
        import os as _os
        _os.environ['DECODE_SPAM_HEADERS_WEB'] = '1'

        # Build manually: a string that simulates two nested colour markers
        # (the kind produced by replaceColors after inner processing).
        from html import escape as _escape
        # Simulate: outer=green wrapping inner=yellow text
        inner = '__COLOR_33__|inner text|__END_COLOR__'
        outer = f'__COLOR_32__|prefix {inner} suffix|__END_COLOR__'

        # We need the Logger class – load it
        src = SCRIPT.read_text(encoding='utf-8')
        globs = {'__name__': '__test__', '__file__': str(SCRIPT)}
        exec(compile(src, str(SCRIPT), 'exec'), globs)
        Logger = globs['Logger']

        result = Logger.htmlColors(outer)

        # Should contain properly nested font tags, no stray </font>
        open_count  = result.count('<font ')
        close_count = result.count('</font>')
        assert open_count == close_count, \
            f'Nested marker test: {open_count} opens vs {close_count} closes in:\n{result}'
        # Plain text should be escaped; no raw &lt;/font&gt; artefacts
        assert '&lt;/font&gt;' not in result
        assert _escape('inner text') in result or 'inner text' in result
