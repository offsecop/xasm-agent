"""#1992 — the completion debug line counts the records inside the tool
envelope and names the key, so a DRP sweep with 40 items never reads 0."""
from lib.completion_count import describe_record_count


def test_wrapped_drp_envelope_counts_items():
    env = {'success': True, 'output': {'items': [{'url': 'a'}] * 40, 'total': 40}}
    assert describe_record_count(env) == '40 (items)'


def test_flat_findings_still_counted():
    assert describe_record_count({'findings': [1, 2, 3]}) == '3 (findings)'


def test_wrapped_results_counted():
    assert describe_record_count({'success': True, 'output': {'results': []}}) == '0 (results)'


def test_no_list_is_named_not_faked():
    assert describe_record_count({'success': False, 'output': {'error': 'x'}}) == '0 (no findings/items/results list)'
    assert describe_record_count('junk') == 'N/A'
