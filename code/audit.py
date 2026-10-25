"""Evidence-led deletion reconstruction. No case labels or sample answers are read here."""
from collections import defaultdict
from dataclasses import dataclass
import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import unicodedata
from functools import lru_cache


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


@lru_cache(maxsize=150000)
def norm(value):
    value = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    if re.fullmatch(r"\+?[\d ()-]{8,}", value):
        return re.sub(r"\D", "", value)
    return value


def scalars(obj):
    if isinstance(obj, dict):
        for value in obj.values():
            yield from scalars(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from scalars(value)
    elif obj is not None:
        yield str(obj)


TOKENS = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}|\buser_\d+\b|\b[a-fA-F0-9]{64}\b|\+\d[\d ()-]{7,}\d")
RESOURCE = re.compile(r"\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|legal_hold|tombstone|marketing|object|cache|email_delivery)_\d+\b")


class Identities:
    def __init__(self, dataset):
        self.current = read_csv(dataset / "user_identities.csv")
        self.history = read_csv(dataset / "user_audit_log.csv")

    @lru_cache(maxsize=600)
    def at(self, cutoff):
        index = defaultdict(set)
        for person in self.current:
            uid = person["user_id"]
            # Roll back identity changes that had not happened at the audit cutoff.
            state = dict(person)
            changes = sorted((h for h in self.history if h["user_id"] == uid),
                             key=lambda h: h["event_time"], reverse=True)
            for h in changes:
                if h["event_time"] > cutoff:
                    state[h["field_name"]] = h["old_value"]
            values = {uid, *(str(state.get(k, "")) for k in ("name", "email", "phone", "email_hash"))}
            for h in changes:
                if h["event_time"] <= cutoff:
                    values.update([h["old_value"], h["new_value"]])
            # Hashes are identifiers too, including hashes of historical emails.
            for value in list(values):
                if "@" in value:
                    values.add(hashlib.sha256(norm(value).encode()).hexdigest())
            for value in values - {"", "None", "null"}:
                index[norm(value)].add(uid)
        return index


SYSTEM_CATEGORY = {
    "account_service": "USER_PROFILE", "profile_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY", "analytics_platform": "ANALYTICS_PROFILE",
    "backup_service": "BACKUP_ARCHIVE", "integration_service": "DATA_FLOW",
    "support_platform": "SUPPORT_MESSAGE", "support_replica": "SUPPORT_MESSAGE",
    "export_service": "USER_EXPORT", "security_service": "SECURITY_AUDIT_LOG",
    "legal_service": "LEGAL_HOLD_RECORD", "identity_service": "ACCOUNT_TOMBSTONE",
    "marketing_platform": "MARKETING_PROFILE", "object_storage": "SUPPORT_ATTACHMENT",
    "cache_service": "CACHE_ENTRY", "email_delivery_service": "EMAIL_DELIVERY_LOG"}

TABLE_SYSTEM = {
    "customer_profiles": "account_service", "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform", "support_records": "support_platform",
    "customer_exports": "export_service", "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service", "security_audit_records": "security_service",
    "legal_hold_records": "legal_service", "account_tombstones": "identity_service",
    "marketing_profiles": "marketing_platform", "email_delivery_logs": "email_delivery_service"}


def table_system(table):
    for base in sorted(TABLE_SYSTEM, key=len, reverse=True):
        if table.startswith(base):
            return TABLE_SYSTEM[base]
    if "search" in table: return "search_service"
    if "profile" in table or "account" in table: return "account_service"
    if "support" in table: return "support_platform"
    if "legal" in table: return "legal_service"
    return ""


def exposed(record, include_reference=False):
    for key, value in record.items():
        if value in (None, "", "null", "[REDACTED]", "REDACTED", "ANONYMIZED"):
            continue
        if any(s in key for s in ("email", "phone", "full_name", "display_name", "requester_name")) or key == "name":
            return True
        if include_reference and key in ("user_id", "customer_reference", "subject_reference"):
            return True
        if key in ("message_text", "message_excerpt") and TOKENS.search(str(value)):
            return True
    return False


@dataclass
class Observation:
    system: str
    resource: str
    category: str
    state: str
    time: str
    available: str
    evidence: str
    values: tuple
    channel: str = ""
    priority: int = 2


class Corpus:
    def __init__(self, dataset, image_text):
        self.dataset = Path(dataset)
        self.identities = Identities(self.dataset)
        self.rules = {r["data_category"]: r["required_action"]
                      for r in read_csv(self.dataset / "deletion_rules.csv")}
        self.activities = read_csv(self.dataset / "system_activity.csv")
        self.observations = []
        self.links = []
        self.coverage = []
        self.documents = []
        self.diagnostics = []
        for manifest in read_csv(self.dataset / "evidence_files.csv"):
            path = (self.dataset / manifest["file_path"]).resolve()
            if not path.is_relative_to(self.dataset.resolve()):
                raise ValueError("Evidence path escapes dataset")
            suffix = path.suffix.lower()
            before = len(self.observations)
            if suffix == ".json": self.parse_json(json.loads(path.read_text(encoding="utf-8")), manifest)
            elif suffix == ".sql": self.parse_sql(path.read_text(encoding="utf-8"), manifest)
            elif suffix == ".log": self.parse_log(path.read_text(encoding="utf-8"), manifest)
            elif suffix == ".txt": self.parse_text(path.read_text(encoding="utf-8"), manifest)
            elif suffix == ".pdf":
                import pymupdf
                with pymupdf.open(path) as doc:
                    text = "\n".join(page.get_text(sort=True) for page in doc)
                self.parse_document(text, manifest)
            elif suffix == ".png": self.parse_image(image_text[path.name], manifest)
            else: raise ValueError(f"Unsupported evidence: {suffix}")
            self.coverage.append((manifest["file_id"], suffix, len(self.observations) - before))
        for a in self.activities:
            # Activity claims may ground identity/dependencies, but never establish deletion.
            self.links.append((a["event_time"], a["resource_id"], tuple(scalars(a)), a["activity_id"]))

    def add(self, m, system, resource, category, state, values, time=None, channel="", priority=2):
        if not resource or not system or not state:
            return
        self.observations.append(Observation(system, resource, category, state,
            time or m["captured_at"], m["captured_at"], m["file_id"],
            tuple(scalars(values)), channel, priority))

    def record(self, r, system, m, category=None, time=None, channel="", priority=2):
        category = category or SYSTEM_CATEGORY.get(system, "")
        rid = r.get("resource_id", "")
        time = time or r.get("observed_at") or r.get("recorded_at") or m["captured_at"]
        state = None
        if "result" in r and r["result"] in ("FOUND", "NOT_FOUND", "IDENTIFIABLE", "ANONYMIZED", "REDACTED", "ACTIVE", "DISABLED", "BLOCKED"):
            state = {"FOUND": "PRESENT", "NOT_FOUND": "ABSENT", "IDENTIFIABLE": "EXPOSED"}.get(r["result"], r["result"])
        elif system == "account_service":
            state = "ABSENT" if r.get("status_code") == 404 else "PRESENT"
        elif system == "search_service":
            state = "PRESENT" if "hits" not in r or r["hits"]["total"] else "ABSENT"
        elif system == "integration_service": state = "ACTIVE" if str(r.get("enabled", 1)).lower() in ("1", "true") else "DISABLED"
        elif system == "backup_service": state = "ACTIVE" if str(r.get("restore_allowed", 1)).lower() in ("1", "true") else "BLOCKED"
        elif system == "analytics_platform": state = "EXPOSED" if exposed(r, True) else "ANONYMIZED"
        elif system == "support_platform": state = "EXPOSED" if exposed(r) else "REDACTED"
        elif system == "identity_service": state = "EXPOSED" if exposed(r) else "REDACTED"
        else: state = "PRESENT"
        self.add(m, system, rid, category, state, r, time, channel, priority)

    def parse_json(self, d, m):
        if "service_exports" in d:
            for system, groups in d["service_exports"].items():
                for group, records in groups.items():
                    for r in records: self.record(r, system, m)
        elif "snapshots" in d:
            for snapshot in d["snapshots"]:
                system, time = snapshot["data_store"], snapshot["captured_at"]
                records = snapshot["records"]
                self.documents.append((time, m["captured_at"], system, records, m["file_id"], snapshot.get("collection", "")))
                for r in records: self.record(r, system, m, time=time, channel=snapshot.get("collection", ""), priority=3)
        elif "records" in d:
            inferred = {"analytics_identity_store": "analytics_platform", "user_export_store": "export_service"}.get(d.get("source"), "")
            for r in d["records"]:
                self.record(r, r.get("system", inferred), m, r.get("record_type"))
        else: raise ValueError(f"Unknown JSON layout: {m['file_id']}")

    def parse_sql(self, text, m):
        conn = sqlite3.connect(":memory:")
        # Authorizer permits only an in-memory snapshot; forbids external attachments/extensions.
        conn.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action in
                            (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH) else sqlite3.SQLITE_OK)
        conn.executescript(text)
        conn.row_factory = sqlite3.Row
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            system = table_system(table)
            records = [dict(r) for r in conn.execute('SELECT * FROM "' + table.replace('"', '""') + '"')]
            if records and "record_json" in records[0]:
                groups = defaultdict(list)
                for row in records:
                    origin = row["origin_system"]
                    r = json.loads(row["record_json"])
                    groups[origin].append(r)
                    self.record(r, origin, m, time=m["captured_at"], channel=table, priority=3)
                for origin, group in groups.items():
                    self.documents.append((m["captured_at"], m["captured_at"], origin, group, m["file_id"], table))
                continue
            if not system: continue
            self.documents.append((m["captured_at"], m["captured_at"], system, records, m["file_id"], table))
            for r in records:
                self.record(r, system, m, time=m["captured_at"], channel=table, priority=3)
        conn.close()

    def parse_text(self, text, m):
        for line in text.splitlines():
            parts = [x.strip() for x in line.lstrip("- ").split("|")]
            if len(parts) == 6:
                t, system, rid, category, result, subject = parts
                self.record({"resource_id": rid, "result": result, "subject_reference": subject},
                            system, m, category, t)

    def parse_log(self, text, m):
        parsed, traces = [], defaultdict(list)
        for line in text.splitlines():
            time = line[:20]
            if not re.match(r"\d{4}-\d\d-\d\dT", time): continue
            line = line.replace('\\"', '"')
            obj = {}
            if "{" in line:
                try: obj = json.loads(line[line.index("{"):])
                except json.JSONDecodeError: pass
            if not obj:
                obj = {k: q if q else v for k, q, v in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line)}
            if " | " in line:
                parts = line.split(" | ")
                if len(parts) >= 6: obj.update(service=parts[2], trace_id=parts[3], event=parts[4])
            bracket = re.search(r"\[(DEBUG|INFO|WARN|ERROR)\] \[([^]]+)\] \[([^]]+)\] (\w+):", line)
            if bracket: obj.update(service=bracket[2], trace_id=bracket[3], event=bracket[4])
            syslog = re.search(r"<\d+>1 \S+ (\w+) (\S+) - -", line)
            if syslog: obj.update(service=syslog[1], trace_id=syslog[2])
            obj["_line"] = line
            trace = obj.get("trace_id") or obj.get("requestId")
            if trace: traces[trace].append(obj)
            parsed.append((time, obj, trace))
        for time, o, trace in parsed:
            event, rid = o.get("event", ""), o.get("resource_id", "")
            system = o.get("system") or o.get("service") or o.get("function", "")
            if system == "profile_service": system = "account_service"
            if event == "record_lookup":
                self.record(o, system, m, o.get("record_type"), time)
                continue
            if not rid: continue
            category, state = SYSTEM_CATEGORY.get(system, ""), None
            if event == "profile_lookup_completed": state = "ABSENT" if str(o.get("rows")) == "0" or str(o.get("http_status")) == "404" else "PRESENT"
            elif event == "index_query_completed": state = "ABSENT" if o.get("result") == "miss" or str(o.get("total_hits")) == "0" else "PRESENT"
            elif event in ("message_pii_scan", "attachment_pii_scan", "analytics_identity_scan"): state = "EXPOSED"
            elif event in ("analytics_profile_read", "analytics_profile_read_completed"):
                state = "EXPOSED" if o.get("direct_identifiers") == "1" or exposed(o, True) else "ANONYMIZED"
            elif event in ("connector_heartbeat", "connector_config_loaded", "connector_config_read_completed"):
                state = "ACTIVE" if str(o.get("enabled")).lower() == "true" else "DISABLED"
            elif event in ("restore_authorization_completed", "restore_candidate_evaluated", "restore_policy_read_completed"):
                state = "BLOCKED" if o.get("decision") == "deny" or str(o.get("restore_allowed")).lower() == "false" or o.get("deletion_block") == "true" else "ACTIVE"
            elif event in ("export_download_check_completed", "export_metadata_read_completed"):
                state = "PRESENT" if o.get("available") == "true" else "ABSENT"
            elif event in ("audit_record_read_completed", "retained_order_loaded"): state = "PRESENT"
            elif event == "message_read": state = "REDACTED" if o.get("message_text") == "[REDACTED]" else "EXPOSED"
            elif event == "support_ticket_read_completed": state = "EXPOSED" if exposed(o) else "REDACTED"
            elif event in ("contact_lookup_completed", "contact_query_completed"):
                state = "PRESENT" if o.get("rows") == "1" else "ABSENT"
                category = "SECONDARY_IDENTIFIER"
                if system == "support_replica": system = "support_platform"
            elif event == "deletion_marker_check" and o.get("marker_found") == "false":
                state, category = "PRESENT", "SECONDARY_IDENTIFIER"
                if system == "support_replica": system = "support_platform"
            if event == "attachment_pii_scan": category = "SUPPORT_ATTACHMENT"
            # Query keys carry identity, but are NOT evidence of fields remaining in a record.
            values = [o, *traces.get(trace, [])] if trace else o
            self.add(m, system, rid, category, state, values, time)

    def parse_document(self, text, m):
        # Business artifacts establish content/presence, not workflow completion.
        self.links.extend((m["captured_at"], rid, (text,), m["file_id"]) for rid in set(RESOURCE.findall(text)))
        for rid in set(RESOURCE.findall(text)):
            if rid.startswith("audit_record_"): system, category, state = "security_service", "SECURITY_AUDIT_LOG", "PRESENT"
            elif rid.startswith("support_"): system, category, state = "support_platform", "SUPPORT_ATTACHMENT", "PRESENT"
            elif rid.startswith("export_"): system, category, state = "export_service", "USER_EXPORT", "PRESENT"
            else: continue
            self.add(m, system, rid, category, state, text, priority=3)
        # Invoice/document reference may map to a resource only via the activity catalog.
        self.documents.append((m["captured_at"], m["captured_at"], "document", text, m["file_id"], "document"))

    def parse_image(self, text, m):
        # OCR business semantics, never a filename->answer mapping.
        low = text.casefold()
        rid_list = list(dict.fromkeys(RESOURCE.findall(text.replace("account _", "account_"))))
        for rid in rid_list:
            if rid.startswith("account_"): system, cat, state = "account_service", "USER_PROFILE", "PRESENT"
            elif rid.startswith("search_"): system, cat, state = "search_service", "SEARCH_INDEX_ENTRY", "PRESENT"
            elif rid.startswith("analytics_"): system, cat, state = "analytics_platform", "ANALYTICS_PROFILE", "EXPOSED"
            elif rid.startswith("support_"): system, cat, state = "support_platform", "SUPPORT_MESSAGE", "EXPOSED"
            elif rid.startswith("data_flow_"): system, cat, state = "integration_service", "DATA_FLOW", "ACTIVE" if "continuous" in low or "delivered" in low else "DISABLED"
            elif rid.startswith("backup_"): system, cat, state = "backup_service", "BACKUP_ARCHIVE", "ACTIVE"
            elif rid.startswith("export_"): system, cat, state = "export_service", "USER_EXPORT", "PRESENT"
            elif rid.startswith("marketing_"): system, cat, state = "marketing_platform", "MARKETING_PROFILE", "PRESENT"
            elif rid.startswith("audit_record_"): system, cat, state = "security_service", "SECURITY_AUDIT_LOG", "PRESENT"
            else: continue
            # Each screenshot can show unrelated resources. Use local lines, and catalog
            # links for the selected panel, instead of attaching the whole screen to all rows.
            lines = text.splitlines()
            positions = [i for i, line in enumerate(lines) if rid in line]
            local = "\n".join(lines[max(0, i - 1):i + 2][j] for i in positions for j in range(len(lines[max(0, i - 1):i + 2])))
            self.add(m, system, rid, cat, state, local, priority=3)
        # Retained customer key has no PII and may omit the internal tombstone resource ID.
        self.documents.append((m["captured_at"], m["captured_at"], "image", text, m["file_id"], "image"))

    @staticmethod
    def subjects(values, index):
        strong, names = set(), set()
        for key in identity_keys(tuple(values)):
            users = index.get(key, ())
            if "@" in key or re.fullmatch(r"user_\d+|[a-f0-9]{64}|\d{8,}", key):
                strong.update(users)
            elif len(users) == 1:
                names.update(users)
        # Names are a fallback, never a reason to merge different people's records
        # when a direct identifier already establishes the subject.
        return strong or names

    def reconstruct(self, request):
        cutoff = request["audit_at"]
        index = self.identities.at(cutoff)
        subjects = index.get(norm(request["email"]), set())
        if len(subjects) != 1: raise ValueError(f"Ambiguous/unresolved subject: {request['case_id']}")
        uid = next(iter(subjects))
        observations = [o for o in self.observations if o.available <= cutoff and o.time <= cutoff]
        resource_subjects = defaultdict(set)
        for o in observations:
            resource_subjects[o.resource].update(self.subjects(o.values, index))
        links = [l for l in self.links if l[0] <= cutoff]
        for t, rid, values, evidence in links:
            resource_subjects[rid].update(self.subjects(values, index))
        relevant = {rid for rid, users in resource_subjects.items() if uid in users}
        # Resource IDs in catalog aliases can connect PDFs/images without exposing an email.
        extra = []
        for t, avail, typ, content, evidence, channel in self.documents:
            if t > cutoff or avail > cutoff or typ not in ("document", "image"): continue
            for lt, rid, values, le in links:
                if rid not in relevant: continue
                aliases = re.findall(r"\(([^()]+)\)", " ".join(values))
                if any(alias in content for alias in aliases) and not any(o.resource == rid and o.evidence == evidence for o in observations):
                    if typ == "document" and any(("statement " + alias).casefold() in content.casefold() for alias in aliases):
                        extra.append(Observation("export_service", rid, "USER_EXPORT", "PRESENT", t, avail, evidence, (content,), priority=3))
                    elif typ == "image" and "customer reference registry" in content.casefold() and rid.startswith("tombstone_"):
                        # A stable reference alone is permitted in an account tombstone.
                        extra.append(Observation("identity_service", rid, "ACCOUNT_TOMBSTONE", "REDACTED", t, avail, evidence, (content,), priority=3))
                    elif typ == "image" and "object storage" in content.casefold() and rid.startswith("object_"):
                        extra.append(Observation("object_storage", rid, "SUPPORT_ATTACHMENT", "PRESENT", t, avail, evidence, (content,), priority=3))
        observations.extend(extra)
        relevant.update(o.resource for o in extra)
        file_subjects = defaultdict(set)
        for o in observations:
            file_subjects[o.evidence].update(self.subjects(o.values, index))
        # Complete point-in-time collection exports prove absence for a resource
        # already linked to this subject. Never invent an ID from case/user numbering.
        for t, avail, system, records, evidence, channel in self.documents:
            if t > cutoff or avail > cutoff or not isinstance(records, list): continue
            if system != "account_service": continue
            if uid not in file_subjects[evidence]: continue
            present = {r.get("resource_id") for r in records}
            for rid in relevant - present:
                prior = [o for o in observations if o.resource == rid and o.system == system and o.time <= t]
                if prior:
                    observations.append(Observation(system, rid, "USER_PROFILE", "ABSENT", t, avail, evidence,
                                                    (uid,), channel, 3))
        grouped = defaultdict(list)
        for o in observations:
            if o.resource in relevant and o.time >= request["requested_at"]: grouped[o.resource].append(o)
        states = []
        for rid, candidates in grouped.items():
            # Distinct replicas are independent copies: an absent primary never erases
            # a replica's positive row. Later verified deletion of the same channel wins.
            candidates.sort(key=lambda o: (o.time, o.priority, o.evidence))
            chosen = candidates[-1]
            channel_latest = {}
            for o in candidates:
                if o.channel: channel_latest[o.channel] = o
            bad = [o for o in channel_latest.values() if "replica" in o.channel and o.state in ("PRESENT", "EXPOSED")]
            if bad and chosen.state in ("ABSENT", "REDACTED", "ANONYMIZED"):
                chosen = max(bad, key=lambda o: (o.time, o.priority))
            # Preserve category information discovered in attachments or secondary stores.
            if chosen.category == "SUPPORT_MESSAGE" and any(o.category == "SUPPORT_ATTACHMENT" for o in candidates):
                chosen = Observation(**{**chosen.__dict__, "category": "SUPPORT_ATTACHMENT"})
            states.append(chosen)
        return uid, states

    def decide(self, request, authorized):
        if not authorized:
            return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}
        uid, states = self.reconstruct(request)
        findings, remedies, verification = [], [], []
        for o in states:
            action = self.rules.get(o.category)
            if o.category == "DATA_FLOW": action = "DISABLE"
            if o.category == "BACKUP_ARCHIVE": action = "BLOCK"
            if not action:
                raise ValueError(f"Unmapped policy category {o.category}")
            desired, check, remediate, finding = {
                "DELETE": ("ABSENT", "VERIFY_RECORD_ABSENT", "DELETE_RECORD", "REPORT_REMAINING_RECORD"),
                "REDACT": ("REDACTED", "VERIFY_RECORD_REDACTED", "REDACT_RECORD", "REPORT_EXPOSED_PII"),
                "ANONYMIZE": ("ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZE_RECORD", "REPORT_EXPOSED_PII"),
                "RETAIN": ("PRESENT", "VERIFY_RECORD_PRESENT", None, None),
                "DISABLE": ("DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLE_DATA_FLOW", "REPORT_ACTIVE_DATA_FLOW"),
                "BLOCK": ("BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCK_RESTORE", "REPORT_RESTORE_RISK")}[action]
            if o.state != desired:
                if action == "RETAIN":
                    raise ValueError(f"Required retained record missing: {o.resource}; no permitted repair operation")
                finding_state = "ACTIVE" if action in ("DISABLE", "BLOCK") else "PRESENT"
                findings.append(step("FINDING", o.system, o.resource, finding, finding_state, o.evidence))
                remedies.append(step("REMEDIATION", o.system, o.resource, remediate, desired, ""))
            verification.append(step("VERIFICATION", o.system, o.resource, check, desired, o.evidence))
        if not states:
            # A missing identity-to-resource link is not proof of successful deletion.
            self.diagnostics.append({"case_id": request["case_id"], "issue": "No attributable state evidence; cannot prove completion"})
            return {"case_id": request["case_id"], "deletion_status": "INCOMPLETE", "steps_json": "[]"}
        incomplete = bool(findings)
        if incomplete:
            for s in verification: s["evidence_id"] = ""
        steps = findings + remedies + verification
        steps.sort(key=lambda s: (PHASES.index(s["phase"]), OPERATIONS[s["phase"]].index(s["operation"]), s["system_id"], s["resource_id"]))
        for n, s in enumerate(steps, 1): s["step_no"] = n
        return {"case_id": request["case_id"], "deletion_status": "INCOMPLETE" if incomplete else "COMPLETE",
                "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))}


PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
OPERATIONS = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"],
    "VERIFICATION": ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]}


def step(phase, system, resource, operation, state, evidence):
    return dict(step_no=0, phase=phase, system_id=system, resource_id=resource,
                operation=operation, state=state, evidence_id=evidence)


@lru_cache(maxsize=50000)
def identity_keys(values):
    keys = set()
    for value in values:
        keys.add(norm(value))
        keys.update(norm(t) for t in TOKENS.findall(str(value)))
    return tuple(keys)
