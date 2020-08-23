import pytest


def render_lines(line_numbers):
    return [
        {
            'type': 'TaintAnomaly',
            'message': 'Tainted input is passed to the sink',
            'line_no': x
        } for x in line_numbers
    ]


def test_blackbox_after_if(fixtures):
    pass # TODO


def test_command_injection(fixtures):
    lines = [18]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/command_injection.py', matches)


def test_command_injection_with_aliases(fixtures):
    lines = [17, 18, 19, 20, 21, 22]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/command_injection_with_aliases.py', matches)


def test_django_XSS(fixtures):
    lines = [5]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/django_XSS.py', matches)


def test_ensure_saved_scope(fixtures):
    lines = [20]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/ensure_saved_scope.py', matches)


def test_inter_command_injection(fixtures):
    lines = [15]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/inter_command_injection.py', matches)


def test_inter_command_injection_2(fixtures):
    lines = [22]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/inter_command_injection_2.py', matches)


def test_list_append(fixtures):
    lines = [13]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/list_append.py', matches)


def disabled_test_multi_chain(fixtures):
    lines = [16]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/multi_chain.py', matches)


def test_path_traversal(fixtures):
    lines = [20]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/path_traversal.py', matches)


def test_path_traversal_sanitizer(fixtures):
    lines = [12]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/path_traversal_sanitised.py', matches)


def test_path_traversal_sanitised_2(fixtures):
    lines = [12]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/path_traversal_sanitised_2.py', matches)


def test_recursive(fixtures):
    pass # TODO


def test_render_ids(fixtures):
    pass  # TODO


def test_simple_vulnerability(fixtures):
    lines = [4]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/simple_vulnerability.py', matches)


def test_xss(fixtures):
    lines = [9, 10]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS.py', matches)


def test_XSS_assign_to_other_var(fixtures):
    lines = [11, 12]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_assign_to_other_var.py', matches)


def test_XSS_call(fixtures):
    lines = [18, 19]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_call.py', matches)


def test_XSS_form(fixtures):
    lines = [15, 16, 17]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_form.py', matches)


def test_xss_reassign(fixtures):
    lines = [11, 12]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_reassign.py', matches)


def test_XSS_url(fixtures):
    lines = [9, 10]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_url.py', matches)


def test_XSS_param(fixtures):
    lines = [11, 12]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_variable_assign.py', matches)


def test_XSS_variable_multiple_assign(fixtures):
    lines = [15, 17]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/XSS_variable_multiple_assign.py', matches)


def test_yield(fixtures):
    lines = [16]
    matches = render_lines(lines)
    fixtures.scan_and_match('pyt_examples/yield.py', matches)


@pytest.mark.parametrize("fpath", (
    "pyt_examples/XSS_variable_assign_no_vuln.py",
    "pyt_examples/XSS_sanitised.py",
    "pyt_examples/XSS_no_vuln.py"
))
def test_no_vuln(fpath, fixtures):
    excludes = [{
        "type": "TaintAnomaly"
    }]
    assert not fixtures.scan_and_match(fpath, matches=[], excludes=excludes)
