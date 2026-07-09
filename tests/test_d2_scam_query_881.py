"""#881 — the D.2 support-scam query must NOT send the bare "+1" operator (Twitter
tokenizes it to match any tweet containing `1`). The +1 phone signal is enforced
by the ingestion-side scam-marker gate (phone regex on post text) instead."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.twitterapi_pattern import _compose_query


def test_d2_query_drops_bare_plus_one_operator():
    q = _compose_query('D.2', brand='lumenfield', handle='lumenfield')
    assert '"+1"' not in q, f'the bare "+1" operator must be removed: {q}'
    # The genuine scam markers still scope the query.
    assert '"DM us"' in q
    assert 'url:t.me' in q and 'url:wa.me' in q


def test_d2_query_is_a_reply_scoped_search():
    q = _compose_query('D.2', brand='lumenfield', handle='lumenfield')
    assert 'to:lumenfield' in q and '-from:lumenfield' in q
