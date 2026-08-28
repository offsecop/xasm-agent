"""#1491 — VIP-exposure contact-noun attribution + residence-term precision.

Live-tenant audit (2026-07): ~12/17 contact_exposure rows carried contact info
belonging to a THIRD PARTY (a think-tank donation mailbox, another person's
phone in a regulator bulletin), or no contact data at all (press-release prose
matched via substring 'address'-in-"addressing"), and one HIGH/80 was the
company's own corporate-HQ street address elevated by generic property terms
in the residence cohort.

Locks (precision AND recall, per the harness doctrine):
  - word-boundary contact nouns: 'addressing'/'contacted' never fire;
  - attribution gate: third-party contact info stays PUBLIC_MENTION/LOW;
    VIP-attributed contact info keeps CONTACT_EXPOSURE/MEDIUM;
  - data-broker HOST classification (the true-positive class) is untouched;
  - residence elevation requires residence-SPECIFIC terms or a municipal
    records host — commercial-property vocabulary alone never elevates.

FICTITIOUS exec/brand (Jane Synth / Lumenfield / .test) only, per the
synthetic-data principle.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.brand_monitor_vip_exposure import (  # noqa: E402
    _classify_exposure,
    _classify_serp_host,
    _contact_noun_attributed,
    _serp_hit_to_finding,
)


def _classify(title, snippet, url='https://blog.test/post',
              name='Jane Synth', company='Lumenfield',
              domain='lumenfield.test', email=''):
    return _classify_exposure('WEB', title, snippet, url, name, company,
                              domain, email)


class TestContactNounWordBoundary:
    """Substring-match FP class: contact nouns must match as whole words."""

    def test_addressing_does_not_fire_contact_exposure(self):
        # Press-release prose: exec quoted, zero contact data. The old
        # substring scan matched 'address' inside "addressing" → MEDIUM 52-60.
        c = _classify(
            'Lumenfield launches Product',
            'Jane Synth, president and CEO: "With Product, we are continuing '
            'addressing our customers\' needs across the region."',
        )
        assert c['exposureType'] == 'PUBLIC_MENTION'
        assert c['severity'] == 'LOW'

    def test_contacted_does_not_fire_contact_exposure(self):
        c = _classify(
            'Industry update',
            'Reporters contacted Jane Synth for comment on the announcement.',
        )
        assert c['exposureType'] == 'PUBLIC_MENTION'
        assert c['severity'] == 'LOW'


class TestContactNounAttribution:
    """Third-party contact info near an incidental exec mention is a public
    mention, not the exec's contact exposure."""

    def test_third_party_mailbox_far_from_name_is_low(self):
        # Think-tank annual report shape: donation mailbox, exec named far away.
        filler = ' '.join(['word'] * 30)
        c = _classify(
            'Annual report',
            f'Jane Synth attended the gala. {filler} Call in your donation '
            f'or email giving@thinktank.test today.',
        )
        assert c['exposureType'] == 'PUBLIC_MENTION'
        assert c['severity'] == 'LOW'

    def test_other_persons_phone_far_from_name_is_low(self):
        # Regulator-bulletin shape: contact block names a DIFFERENT person.
        filler = ' '.join(['x'] * 25)
        c = _classify(
            'Regulatory bulletin',
            f'The panel reviewed submissions from Jane Synth. {filler} '
            f'For details contact Alex Reviewer at 555-0100.',
        )
        assert c['exposureType'] == 'PUBLIC_MENTION'
        assert c['severity'] == 'LOW'

    def test_brand_domain_mailbox_keeps_medium(self):
        # An @brand-domain mailbox anywhere in the text is attribution (recall).
        filler = ' '.join(['pad'] * 20)
        c = _classify(
            'Directory listing',
            f'Jane Synth. {filler} Email j.synth@lumenfield.test, phone on file.',
        )
        assert c['exposureType'] == 'CONTACT_EXPOSURE'
        assert c['severity'] == 'MEDIUM'

    def test_masked_brand_domain_mailbox_keeps_medium(self):
        # Data-broker masked local part still carries the @brand-domain side.
        filler = ' '.join(['pad'] * 20)
        c = _classify(
            'People search',
            f'Jane Synth. {filler} e******@lumenfield.test and one phone number.',
        )
        assert c['exposureType'] == 'CONTACT_EXPOSURE'
        assert c['severity'] == 'MEDIUM'

    def test_contact_noun_adjacent_to_name_keeps_medium(self):
        c = _classify(
            'Jane Synth bio',
            'Jane Synth — email and phone listed on request.',
        )
        assert c['exposureType'] == 'CONTACT_EXPOSURE'
        assert c['severity'] == 'MEDIUM'

    def test_vip_email_exact_match_keeps_medium(self):
        filler = ' '.join(['pad'] * 20)
        c = _classify(
            'Roster',
            f'Jane Synth. {filler} Reach her: jane@personalmail.test (email).',
            email='jane@personalmail.test',
        )
        assert c['exposureType'] == 'CONTACT_EXPOSURE'
        assert c['severity'] == 'MEDIUM'

    def test_attribution_helper_rejects_no_signal(self):
        assert _contact_noun_attributed(
            'a page about jane synth with a mailbox elsewhere '
            + ' '.join(['t'] * 30) + ' email info@other.test',
            'Jane Synth', 'lumenfield.test', '',
        ) is False


class TestDataBrokerHostUntouched:
    """The HOST-axis true-positive class must keep working unchanged."""

    def test_data_broker_person_page_still_medium_contact_exposure(self):
        c = _classify_serp_host('https://www.zoominfo.com/p/Jane-Synth/42',
                                [], [], ['lumenfield'], 'Jane Synth')
        assert c is not None
        assert c['action'] == 'flag'
        assert c['exposureType'] == 'CONTACT_EXPOSURE'
        assert c['severity'] == 'MEDIUM'


class TestResidenceTermPrecision:
    """Generic commercial-property vocabulary must not elevate a corporate
    address to HIGH; residence-specific terms and municipal hosts still do."""

    def test_corporate_zoning_page_not_elevated(self):
        # Corporate-HQ shape: company office address + commercial 'zoning'
        # prose on a non-municipal host. Old terms list elevated this to
        # HIGH/80 CONTACT_EXPOSURE (RESIDENCE_EXPOSURE hostClass).
        hit = {'url': 'https://commercial-realty.test/listing/9',
               'title': 'Lumenfield head office',
               'snippet': 'Jane Synth of Lumenfield. Head office at 100 Main '
                          'St, zoning approved for commercial land use, '
                          'property owner of record.',
               '_cohort': 'residence', '_query': 'q', '_page': 1}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', 'Lumenfield',
                                 'lumenfield.test', [], [], ['lumenfield'])
        # No residence-specific signal → the hit is dropped, never HIGH-flooded.
        assert f is None or f['metadata'].get('hostClass') != 'RESIDENCE_EXPOSURE'
        if f is not None:
            assert f['severity'] != 'HIGH'

    def test_home_address_term_still_elevates(self):
        hit = {'url': 'https://local-forum.test/thread/1',
               'title': 'Filing',
               'snippet': 'Jane Synth home address listed as 12 Example Rd.',
               '_cohort': 'residence', '_query': 'q', '_page': 1}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', '', '',
                                 [], [], [])
        assert f is not None
        assert f['severity'] == 'HIGH'
        assert f['metadata']['hostClass'] == 'RESIDENCE_EXPOSURE'

    def test_municipal_host_still_elevates(self):
        hit = {'url': 'https://pub-town.escribemeetings.com/doc.ashx?id=1',
               'title': 'Committee agenda',
               'snippet': 'Applicant Jane Synth, 12 Example Rd.',
               '_cohort': 'residence', '_query': 'q', '_page': 1}
        f = _serp_hit_to_finding('vip-1', hit, 'Jane Synth', '', '',
                                 [], [], [])
        assert f is not None
        assert f['severity'] == 'HIGH'
        assert f['metadata']['hostClass'] == 'RESIDENCE_EXPOSURE'
