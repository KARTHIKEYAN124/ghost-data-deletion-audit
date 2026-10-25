"""Independent synthetic cases: no contest labels, identifiers, or expected files."""
from collections import defaultdict
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit import Corpus, Identities, Observation
from local_model import authorize


class FixtureIdentity:
    def at(self, cutoff):
        return {"person@example.test": {"subject_alpha"}, "subject_alpha": {"subject_alpha"}}


def fixture(observations):
    corpus = Corpus.__new__(Corpus)
    corpus.identities = FixtureIdentity()
    corpus.observations = observations
    corpus.documents, corpus.links, corpus.activities, corpus.diagnostics = [], [], [], []
    corpus.rules = {"USER_PROFILE": "DELETE", "SUPPORT_MESSAGE": "REDACT",
                    "ANALYTICS_PROFILE": "ANONYMIZE", "SECURITY_AUDIT_LOG": "RETAIN",
                    "ACCOUNT_TOMBSTONE": "REDACT"}
    return corpus


def obs(system, resource, category, state, date="2026-02-10", channel=""):
    return Observation(system, resource, category, state, date + "T12:00:00Z",
                       date + "T12:00:00Z", "fixture_evidence", ("subject_alpha",), channel)


REQUEST = dict(case_id="synthetic", email="person@example.test", requested_at="2026-02-01T00:00:00Z",
               reported_status="COMPLETE", reported_at="2026-02-02T00:00:00Z", audit_at="2026-02-15T00:00:00Z")


class AuditSafetyTests(unittest.TestCase):
    def test_name_collision_does_not_merge_people(self):
        index = {"shared name": {"person_a", "person_b"}, "a@example.test": {"person_a"},
                 "unique name": {"person_b"}}
        self.assertEqual(Corpus.subjects(("Shared Name",), index), set())
        self.assertEqual(Corpus.subjects(("Unique Name", "a@example.test"), index), {"person_a"})

    def test_non_deletion_and_negation(self):
        for text in ["Only unsubscribe me from marketing lists; keep my account.",
                     "Do not delete my account. Send an export.",
                     "Correct my name without removing my records."]:
            self.assertFalse(authorize(text, True))
        self.assertEqual(fixture([]).decide(REQUEST, False)["steps_json"], "[]")

    def test_recreation_stopped_before_pii_cleanup(self):
        c = fixture([obs("account_service", "profile_alpha", "USER_PROFILE", "PRESENT"),
                     obs("integration_service", "connector_alpha", "DATA_FLOW", "ACTIVE"),
                     obs("support_platform", "ticket_alpha", "SUPPORT_MESSAGE", "EXPOSED"),
                     obs("security_service", "journal_alpha", "SECURITY_AUDIT_LOG", "PRESENT")])
        r = c.decide(REQUEST, True)
        steps = json.loads(r["steps_json"])
        self.assertEqual(r["deletion_status"], "INCOMPLETE")
        repairs = [s["operation"] for s in steps if s["phase"] == "REMEDIATION"]
        self.assertEqual(repairs, ["DISABLE_DATA_FLOW", "DELETE_RECORD", "REDACT_RECORD"])
        self.assertFalse(any(s["resource_id"] == "journal_alpha" and s["phase"] == "REMEDIATION" for s in steps))
        self.assertTrue(all(s["evidence_id"] == "" for s in steps if s["phase"] != "FINDING"))

    def test_future_evidence_cannot_change_cutoff(self):
        old = obs("account_service", "profile_alpha", "USER_PROFILE", "PRESENT")
        future = obs("account_service", "profile_alpha", "USER_PROFILE", "ABSENT", "2026-03-01")
        self.assertEqual(fixture([old, future]).decide(REQUEST, True)["deletion_status"], "INCOMPLETE")

    def test_replica_survives_absent_primary(self):
        replica = obs("account_service", "profile_alpha", "USER_PROFILE", "PRESENT", channel="profiles_replica")
        primary = obs("account_service", "profile_alpha", "USER_PROFILE", "ABSENT", "2026-02-11", "profiles_primary")
        self.assertEqual(fixture([replica, primary]).decide(REQUEST, True)["deletion_status"], "INCOMPLETE")

    def test_verified_replica_cleanup_supersedes_old_positive(self):
        old = obs("account_service", "profile_alpha", "USER_PROFILE", "PRESENT", channel="profiles_replica")
        new = obs("account_service", "profile_alpha", "USER_PROFILE", "ABSENT", "2026-02-11", "profiles_replica")
        self.assertEqual(fixture([old, new]).decide(REQUEST, True)["deletion_status"], "COMPLETE")

    def test_tombstone_and_retention_are_preserved(self):
        c = fixture([obs("identity_service", "reference_alpha", "ACCOUNT_TOMBSTONE", "REDACTED"),
                     obs("security_service", "journal_alpha", "SECURITY_AUDIT_LOG", "PRESENT")])
        r = c.decide(REQUEST, True)
        self.assertEqual(r["deletion_status"], "COMPLETE")
        self.assertEqual([s["operation"] for s in json.loads(r["steps_json"])],
                         ["VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED"])

    def test_historical_email_hash_is_resolved(self):
        from hashlib import sha256
        identities = Identities.__new__(Identities)
        identities.current = [dict(user_id="subject_alpha", name="Test Person", email="new@example.test",
                                   phone="", email_hash="", updated_at="2026-02-10T00:00:00Z")]
        identities.history = [dict(user_id="subject_alpha", field_name="email", old_value="old@example.test",
                                   new_value="new@example.test", event_time="2026-02-10T00:00:00Z")]
        after = identities.at("2026-02-15T00:00:00Z")
        before = identities.at("2026-02-05T00:00:00Z")
        self.assertEqual(after[sha256(b"old@example.test").hexdigest()], {"subject_alpha"})
        self.assertNotIn("new@example.test", before)


if __name__ == "__main__":
    unittest.main()
