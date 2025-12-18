# -*- coding: utf-8 -*-
import json
import random
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional, Set, Dict, Any, Tuple

import streamlit as st
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload


# ============================================================
# Google Drive helpers
# ============================================================

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"


@st.cache_resource
def get_drive_service():
    creds_dict = dict(st.secrets["gcp_service_account"])
    creds = Credentials.from_service_account_info(creds_dict, scopes=[DRIVE_SCOPE])
    return build("drive", "v3", credentials=creds)


def _folder_id() -> str:
    return str(st.secrets["GDRIVE_FOLDER_ID"]).strip()


def drive_find_file_id(service, filename: str) -> Optional[str]:
    # Find exact filename inside folder
    q = (
        f"name = '{filename}' and "
        f"'{_folder_id()}' in parents and "
        "trashed = false"
    )
    resp = service.files().list(q=q, fields="files(id,name)").execute()
    files = resp.get("files", [])
    return files[0]["id"] if files else None


def drive_read_json(service, filename: str, default):
    file_id = drive_find_file_id(service, filename)
    if not file_id:
        return default
    data = service.files().get_media(fileId=file_id).execute()
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return default


def drive_write_json(service, filename: str, obj) -> None:
    content = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    media = MediaInMemoryUpload(content, mimetype="application/json")

    file_id = drive_find_file_id(service, filename)
    if file_id:
        service.files().update(fileId=file_id, media_body=media).execute()
    else:
        metadata = {
            "name": filename,
            "parents": [_folder_id()],
            "mimeType": "application/json",
        }
        service.files().create(body=metadata, media_body=media, fields="id").execute()


def safe_user_key(username: str) -> str:
    # keep filenames safe and consistent
    return "".join(c for c in username.strip() if c.isalnum() or c in ("_", "-", ".")).strip()


def users_filename() -> str:
    return "users.json"


def bank_filename(username: str) -> str:
    return f"bank_{safe_user_key(username)}.json"


def results_filename(username: str) -> str:
    return f"results_{safe_user_key(username)}.json"


# ============================================================
# Simple auth (stored in Drive)
# ============================================================

def _hash_pw(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def load_users() -> Dict[str, Dict[str, str]]:
    svc = get_drive_service()
    return drive_read_json(svc, users_filename(), {})


def save_users(users: Dict[str, Dict[str, str]]) -> None:
    svc = get_drive_service()
    drive_write_json(svc, users_filename(), users)


def create_user(username: str, password: str) -> Tuple[bool, str]:
    username = username.strip()
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if any(c.isspace() for c in username):
        return False, "Username cannot contain spaces."
    if not password or len(password) < 4:
        return False, "Password must be at least 4 characters."

    users = load_users()
    if username in users:
        return False, "User already exists."

    salt = hashlib.sha256(f"{username}-{random.random()}".encode("utf-8")).hexdigest()[:16]
    users[username] = {"salt": salt, "hash": _hash_pw(password, salt)}
    save_users(users)

    # Initialize empty bank + results
    svc = get_drive_service()
    if drive_find_file_id(svc, bank_filename(username)) is None:
        drive_write_json(svc, bank_filename(username), [])
    if drive_find_file_id(svc, results_filename(username)) is None:
        drive_write_json(svc, results_filename(username), [])

    return True, "Account created."


def verify_login(username: str, password: str) -> Tuple[bool, str]:
    users = load_users()
    if username not in users:
        return False, "User not found."
    salt = users[username]["salt"]
    h = users[username]["hash"]
    if _hash_pw(password, salt) != h:
        return False, "Wrong password."
    return True, "Logged in."


# ============================================================
# Question model
# ============================================================

@dataclass
class BankQuestion:
    id: str
    text: str
    qtype: str  # "single", "multi", "ordering"
    options: List[str]
    category: str = "General"
    tags: List[str] = None

    correct_single: Optional[int] = None
    correct_multi: Optional[List[int]] = None
    correct_order: Optional[List[str]] = None

    max_points: int = 1

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


# ============================================================
# Session defaults
# ============================================================

def ensure_defaults():
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None

    if "show_facit" not in st.session_state:
        st.session_state.show_facit = False
    if "practice_mode" not in st.session_state:
        st.session_state.practice_mode = False
    if "lock_after_submit" not in st.session_state:
        st.session_state.lock_after_submit = True

    if "question_bank" not in st.session_state:
        st.session_state.question_bank = []  # raw dict list

    if "exam" not in st.session_state:
        st.session_state.exam = []
        st.session_state.exam_meta = {}
        st.session_state.answers = {}
        st.session_state.submitted = False
        st.session_state.previous_exam_questions = []
        st.session_state.last_results = []


def do_rerun():
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()


# ============================================================
# Bank + results I/O (Drive)
# ============================================================

def load_bank_for_user(username: str) -> None:
    svc = get_drive_service()
    st.session_state.question_bank = drive_read_json(svc, bank_filename(username), [])


def save_bank_for_user(username: str) -> None:
    svc = get_drive_service()
    drive_write_json(svc, bank_filename(username), st.session_state.question_bank)


def load_results_for_user(username: str) -> List[Dict[str, Any]]:
    svc = get_drive_service()
    return drive_read_json(svc, results_filename(username), [])


def append_result_for_user(username: str, attempt: Dict[str, Any]) -> None:
    svc = get_drive_service()
    results = drive_read_json(svc, results_filename(username), [])
    results.append(attempt)
    drive_write_json(svc, results_filename(username), results)


def load_bank_objects() -> List[BankQuestion]:
    return [BankQuestion(**q) for q in st.session_state.question_bank]


def save_bank_objects(bank: List[BankQuestion]) -> None:
    st.session_state.question_bank = [asdict(q) for q in bank]
    if st.session_state.auth_user:
        save_bank_for_user(st.session_state.auth_user)


def next_id(bank: List[BankQuestion]) -> str:
    used = set(q.id for q in bank if q.id.strip())
    n = 1
    while True:
        cid = f"Q{n}"
        if cid not in used:
            return cid
        n += 1


# ============================================================
# Scoring
# ============================================================

def score_single(correct: int, chosen: Optional[int]) -> int:
    return 1 if chosen is not None and chosen == correct else 0


def score_multi_all_or_nothing(correct: Set[int], chosen: Set[int], maxp: int) -> int:
    return maxp if chosen == correct else 0


def score_ordering_strict(correct: List[str], chosen: List[str], maxp: int) -> int:
    norm_c = [c.strip().lower() for c in correct]
    norm_u = [c.strip().lower() for c in chosen]
    return maxp if norm_u == norm_c else 0


def compute_points(q: BankQuestion, ans_orig: Any) -> int:
    if q.qtype == "single":
        if q.correct_single is None:
            return 0
        return score_single(int(q.correct_single), ans_orig)

    if q.qtype == "multi":
        return score_multi_all_or_nothing(set(q.correct_multi or []), set(ans_orig or set()), int(q.max_points))

    if q.qtype == "ordering":
        if not ans_orig or any(a is None for a in ans_orig) or len(set(ans_orig)) != len(ans_orig):
            return 0
        return score_ordering_strict(list(q.correct_order or []), list(ans_orig), int(q.max_points))

    return 0


def facit_text(q: BankQuestion) -> str:
    if q.qtype == "single":
        return q.options[int(q.correct_single)] if q.correct_single is not None else "(no correct set)"
    if q.qtype == "multi":
        idxs = sorted(q.correct_multi or [])
        return ", ".join(q.options[i] for i in idxs) if idxs else "(no correct set)"
    if q.qtype == "ordering":
        return " → ".join(q.correct_order or [])
    return ""


def user_answer_text(q: BankQuestion, ans_disp: Any, display_opts: List[str]) -> str:
    if ans_disp is None:
        return "(no answer)"
    if q.qtype == "single":
        return display_opts[ans_disp] if isinstance(ans_disp, int) else "(no answer)"
    if q.qtype == "multi":
        chosen = set(ans_disp or set())
        if not chosen:
            return "(no answer)"
        return ", ".join(display_opts[i] for i in sorted(chosen))
    if q.qtype == "ordering":
        if not ans_disp or any(a is None for a in ans_disp):
            return "(incomplete)"
        return " → ".join(ans_disp)
    return str(ans_disp)


def build_wrong_details(q: BankQuestion, ans_disp: Any, meta: Dict[str, Any]) -> str:
    if q.qtype in ("single", "multi"):
        disp = meta["display_options"]
        d2o = meta["display_to_orig"]

        if q.qtype == "single":
            if ans_disp is None:
                return f"You did not answer. Correct: {facit_text(q)}"
            return f"Your answer: {disp[ans_disp]} | Correct: {facit_text(q)}"

        chosen_disp = set(ans_disp or set())
        chosen_orig = {d2o[i] for i in chosen_disp}
        correct_orig = set(q.correct_multi or [])

        missing = sorted(list(correct_orig - chosen_orig))
        extra = sorted(list(chosen_orig - correct_orig))

        parts = [
            "Your selections: " + (", ".join(disp[i] for i in sorted(chosen_disp)) if chosen_disp else "(no answer)"),
            "Correct selections: " + facit_text(q),
        ]
        if missing:
            parts.append("Missing: " + ", ".join(q.options[i] for i in missing))
        if extra:
            parts.append("Incorrectly selected: " + ", ".join(q.options[i] for i in extra))
        return " | ".join(parts)

    if q.qtype == "ordering":
        if not ans_disp or any(a is None for a in ans_disp):
            return f"Incomplete order. Correct: {facit_text(q)}"
        if len(set(ans_disp)) != len(ans_disp):
            return f"Duplicate selected. Correct: {facit_text(q)}"
        for i, (u, c) in enumerate(zip(ans_disp, q.correct_order or []), start=1):
            if u.strip().lower() != c.strip().lower():
                return (
                    f"Wrong at position {i}: you chose '{u}', correct is '{c}'. "
                    f"Your order: {' → '.join(ans_disp)} | Correct: {facit_text(q)}"
                )
        return f"Your order: {' → '.join(ans_disp)} | Correct: {facit_text(q)}"

    return f"Correct: {facit_text(q)}"


# ============================================================
# Quiz engine (build / retry / grade)
# ============================================================

def build_exam_from_questions(questions: List[BankQuestion]) -> None:
    keep = {
        "auth_user": st.session_state.auth_user,
        "question_bank": st.session_state.question_bank,
        "show_facit": st.session_state.show_facit,
        "practice_mode": st.session_state.practice_mode,
        "lock_after_submit": st.session_state.lock_after_submit,
    }

    st.session_state.clear()
    st.session_state.update(keep)
    ensure_defaults()

    st.session_state.exam = questions[:]
    st.session_state.previous_exam_questions = questions[:]
    st.session_state.answers = {}
    st.session_state.submitted = False
    st.session_state.last_results = []

    meta: Dict[int, Dict[str, Any]] = {}
    for idx, q in enumerate(questions, start=1):
        m: Dict[str, Any] = {}
        if q.qtype in ("single", "multi"):
            order = list(range(len(q.options)))
            random.shuffle(order)
            m["display_options"] = [q.options[i] for i in order]
            m["display_to_orig"] = {d: o for d, o in enumerate(order)}
        elif q.qtype == "ordering":
            dropdown = q.options[:]
            random.shuffle(dropdown)
            m["ordering_dropdown"] = dropdown
        meta[idx] = m

    st.session_state.exam_meta = meta


def create_new_random_exam(n_req: int) -> None:
    bank = load_bank_objects()
    if not bank:
        st.warning("Question bank is empty. Add questions first.")
        return
    n = min(n_req, len(bank))
    selected = random.sample(bank, n)
    build_exam_from_questions(selected)


def retry_failed_only(results: List[Dict[str, Any]]) -> None:
    prev: List[BankQuestion] = st.session_state.get("previous_exam_questions", [])
    failed_idx = [r["i"] for r in results if not r["correct"]]
    failed = [prev[i - 1] for i in failed_idx] if prev else []
    if not failed:
        st.info("No failed questions to retry.")
        return
    build_exam_from_questions(failed)


def retry_failed_plus_random(results: List[Dict[str, Any]], extra_random: int) -> None:
    prev: List[BankQuestion] = st.session_state.get("previous_exam_questions", [])
    failed_idx = [r["i"] for r in results if not r["correct"]]
    failed = [prev[i - 1] for i in failed_idx] if prev else []
    if not failed:
        st.info("No failed questions to retry.")
        return

    bank = load_bank_objects()
    failed_ids = {q.id for q in failed}
    remaining = [q for q in bank if q.id not in failed_ids]

    extra = min(int(extra_random), len(remaining))
    extra_qs = random.sample(remaining, extra) if extra > 0 else []
    mixed = failed + extra_qs
    random.shuffle(mixed)
    build_exam_from_questions(mixed)


def grade_exam() -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]]]:
    exam: List[BankQuestion] = st.session_state.exam
    meta: Dict[int, Dict[str, Any]] = st.session_state.exam_meta

    total = 0
    maxp = 0
    results: List[Dict[str, Any]] = []
    cat: Dict[str, Dict[str, int]] = {}

    for i, q in enumerate(exam, start=1):
        m = meta.get(i, {})
        ans_disp = st.session_state.answers.get(i)

        if q.qtype in ("single", "multi"):
            d2o = m["display_to_orig"]
            if q.qtype == "single":
                ans_orig = None if ans_disp is None else d2o[ans_disp]
            else:
                ans_orig = {d2o[x] for x in (ans_disp or set())}
        else:
            ans_orig = ans_disp

        pts = compute_points(q, ans_orig)
        total += pts
        maxp += int(q.max_points)

        cat_key = (q.category or "General").strip() or "General"
        if cat_key not in cat:
            cat[cat_key] = {"score": 0, "max": 0}
        cat[cat_key]["score"] += pts
        cat[cat_key]["max"] += int(q.max_points)

        is_correct = (pts == int(q.max_points))
        display_opts = m.get("display_options", q.options)

        results.append({
            "i": i,
            "qid": q.id,
            "category": cat_key,
            "tags": q.tags or [],
            "question": q.text,
            "points": pts,
            "max_points": int(q.max_points),
            "correct": is_correct,
            "your_answer": user_answer_text(q, ans_disp, display_opts),
            "facit": facit_text(q),
            "details": "" if is_correct else build_wrong_details(q, ans_disp, m),
        })

    st.session_state.last_results = results

    if st.session_state.auth_user:
        attempt = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "n_questions": len(exam),
            "total_score": total,
            "total_max": maxp,
            "category_breakdown": cat,
            "failed_qids": [r["qid"] for r in results if not r["correct"]],
        }
        append_result_for_user(st.session_state.auth_user, attempt)

    return results, cat


# ============================================================
# App UI
# ============================================================

ensure_defaults()
st.set_page_config(page_title="Test Builder + Quiz Runner (Drive)", layout="wide")


# ------------------ LOGIN ------------------

if not st.session_state.auth_user:
    st.title("🔐 Login (Google Drive storage)")

    cols = st.columns(2)
    with cols[0]:
        st.subheader("Log in")
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            ok, msg = verify_login(u.strip(), p)
            if ok:
                st.session_state.auth_user = u.strip()
                load_bank_for_user(st.session_state.auth_user)
                st.success("Logged in.")
                do_rerun()
            else:
                st.error(msg)

    with cols[1]:
        st.subheader("Create account")
        nu = st.text_input("New username", key="new_user")
        np = st.text_input("New password", type="password", key="new_pass")
        if st.button("Create account"):
            ok, msg = create_user(nu.strip(), np)
            if ok:
                st.success(msg + " Now log in.")
            else:
                st.error(msg)

    st.caption("This is a simple login for personal use. Data is stored as JSON files in your Google Drive folder.")
    st.stop()


# ------------------ MAIN ------------------

user = st.session_state.auth_user
st.title("🧪 Test Builder + Quiz Runner")
st.caption(f"Logged in as **{user}**")

with st.sidebar:
    st.header("Account")
    if st.button("Logout", use_container_width=True):
        st.session_state.clear()
        ensure_defaults()
        do_rerun()

    st.divider()
    st.header("Quiz settings")
    bank_objs = load_bank_objects()
    max_q = max(1, len(bank_objs))
    n_req = st.slider("Number of questions", 1, max_q, min(10, max_q))

    st.checkbox("Show answer key (facit)", key="show_facit")
    st.checkbox("Practice mode (instant feedback)", key="practice_mode")
    st.checkbox("Lock test after grading", key="lock_after_submit")

    st.divider()
    if st.button("🎲 Create new random test", use_container_width=True):
        create_new_random_exam(n_req)
        do_rerun()

tabs = st.tabs(["🧱 Build Question Bank", "📝 Take Test", "📊 Results history"])


# ============================================================
# TAB 1: BUILD BANK
# ============================================================

with tabs[0]:
    bank = load_bank_objects()

    st.subheader("Add a new question")

    with st.form("add_question_form", clear_on_submit=True):
        qtype = st.selectbox("Question type", ["single", "multi", "ordering"])
        qtext = st.text_area("Question text", height=90)

        category = st.text_input("Category", value="General")
        tags_raw = st.text_input("Tags (comma-separated)", value="")

        options_raw = st.text_area("Options (one per line)", height=140)
        max_points = st.number_input("Max points", min_value=1, max_value=20, value=1, step=1)

        submitted = st.form_submit_button("➕ Add question")
        if submitted:
            opts = [line.strip() for line in options_raw.splitlines() if line.strip()]
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

            if not qtext.strip():
                st.error("Question text is required.")
            elif qtype in ("single", "multi") and len(opts) < 2:
                st.error("Single/Multi questions need at least 2 options.")
            elif qtype == "ordering" and len(opts) < 2:
                st.error("Ordering questions need at least 2 items.")
            else:
                qid = next_id(bank)
                newq = BankQuestion(
                    id=qid,
                    text=qtext.strip(),
                    qtype=qtype,
                    options=opts,
                    category=category.strip() or "General",
                    tags=tags,
                    max_points=int(max_points),
                )
                bank.append(newq)
                save_bank_objects(bank)
                st.success(f"Added {qid}. Now set the correct answers below.")
                do_rerun()

    st.divider()
    st.subheader(f"Question bank ({len(bank)} questions)")

    if not bank:
        st.info("No questions yet. Add some above.")
    else:
        q_search = st.text_input("Search (text/category/tag)", value="")
        filtered = bank
        if q_search.strip():
            s = q_search.strip().lower()

            def match(q: BankQuestion) -> bool:
                if s in q.id.lower():
                    return True
                if s in q.text.lower():
                    return True
                if s in (q.category or "").lower():
                    return True
                if any(s in t.lower() for t in (q.tags or [])):
                    return True
                return False

            filtered = [q for q in bank if match(q)]

        st.caption(f"Showing {len(filtered)} / {len(bank)}")
        for q in filtered:
            title = f"{q.id} — {q.qtype} — [{q.category}] — {q.text[:70]}{'...' if len(q.text) > 70 else ''}"
            with st.expander(title, expanded=False):
                st.write(q.text)

                new_text = st.text_area("Edit question text", value=q.text, key=f"edit_text_{q.id}", height=80)
                new_category = st.text_input("Category", value=q.category or "General", key=f"cat_{q.id}")
                tags_str = ", ".join(q.tags or [])
                new_tags_raw = st.text_input("Tags (comma-separated)", value=tags_str, key=f"tags_{q.id}")

                opt_text = "\n".join(q.options)
                new_opt_raw = st.text_area("Edit options (one per line)", value=opt_text, key=f"edit_opts_{q.id}", height=140)
                new_opts = [line.strip() for line in new_opt_raw.splitlines() if line.strip()]

                # Correct answer editors
                corr_single = None
                corr_multi = None
                corr_order = None

                if q.qtype == "single":
                    if len(new_opts) >= 2:
                        corr_single = st.radio(
                            "Correct option",
                            options=list(range(len(new_opts))),
                            format_func=lambda idx: new_opts[idx],
                            index=q.correct_single if q.correct_single is not None and q.correct_single < len(new_opts) else None,
                            key=f"corr_single_{q.id}",
                        )
                    else:
                        st.warning("Need at least 2 options.")

                elif q.qtype == "multi":
                    if len(new_opts) >= 2:
                        corr_multi = st.multiselect(
                            "Correct options",
                            options=list(range(len(new_opts))),
                            format_func=lambda idx: new_opts[idx],
                            default=[c for c in (q.correct_multi or []) if c < len(new_opts)],
                            key=f"corr_multi_{q.id}",
                        )
                    else:
                        st.warning("Need at least 2 options.")

                else:  # ordering
                    corr_order = st.multiselect(
                        "Correct order (select items in correct order)",
                        options=new_opts,
                        default=q.correct_order or [],
                        key=f"corr_order_{q.id}",
                        help="Must include every item exactly once, in correct order.",
                    )

                new_points = st.number_input("Max points", min_value=1, max_value=20, value=int(q.max_points), step=1, key=f"pts_{q.id}")

                c1, c2 = st.columns(2)
                with c1:
                    if st.button("💾 Save changes", key=f"save_{q.id}"):
                        q.text = new_text.strip()
                        q.options = new_opts
                        q.category = (new_category.strip() or "General")
                        q.tags = [t.strip() for t in new_tags_raw.split(",") if t.strip()]
                        q.max_points = int(new_points)

                        if q.qtype == "single":
                            q.correct_single = corr_single if isinstance(corr_single, int) else None
                            q.correct_multi = None
                            q.correct_order = None
                        elif q.qtype == "multi":
                            q.correct_multi = list(corr_multi or [])
                            q.correct_single = None
                            q.correct_order = None
                        else:
                            if len(corr_order or []) != len(new_opts) or len(set(corr_order or [])) != len(corr_order or []):
                                st.error("Ordering correct answer must include every item exactly once.")
                                st.stop()
                            q.correct_order = list(corr_order or [])
                            q.correct_single = None
                            q.correct_multi = None

                        save_bank_objects(bank)
                        st.success("Saved (Google Drive).")
                        do_rerun()

                with c2:
                    if st.button("🗑 Delete question", key=f"del_{q.id}"):
                        bank = [qq for qq in bank if qq.id != q.id]
                        save_bank_objects(bank)
                        st.success("Deleted (Google Drive).")
                        do_rerun()

    st.divider()
    st.subheader("Import / Export bank (JSON)")

    colA, colB = st.columns(2)
    with colA:
        export = json.dumps(st.session_state.question_bank, indent=2, ensure_ascii=False)
        st.download_button("⬇️ Download bank.json", data=export.encode("utf-8"), file_name=f"{user}_bank.json", mime="application/json")

    with colB:
        up = st.file_uploader("Upload bank.json", type=["json"])
        if up is not None:
            try:
                data = json.loads(up.read().decode("utf-8"))
                if not isinstance(data, list):
                    raise ValueError("JSON must be a list of questions.")
                _ = [BankQuestion(**item) for item in data]  # validate
                st.session_state.question_bank = data
                save_bank_for_user(user)
                st.success(f"Imported {len(data)} questions (Google Drive).")
                do_rerun()
            except Exception as e:
                st.error(f"Import failed: {e}")


# ============================================================
# TAB 2: TAKE TEST
# ============================================================

with tabs[1]:
    bank = load_bank_objects()

    if not bank:
        st.info("Add questions in **Build Question Bank** first.")
    elif not st.session_state.exam:
        st.info("Click **Create new random test** in the sidebar to start.")
    else:
        exam: List[BankQuestion] = st.session_state.exam
        exam_meta: Dict[int, Dict[str, Any]] = st.session_state.exam_meta

        st.write(f"**Current test:** {len(exam)} questions")

        for idx, q in enumerate(exam, start=1):
            st.markdown("---")
            st.subheader(f"Question {idx} ({q.id})")
            st.caption(f"Category: **{q.category}** | Tags: {', '.join(q.tags or []) if (q.tags or []) else '—'}")
            st.write(q.text)

            disabled = st.session_state.submitted and st.session_state.lock_after_submit
            meta = exam_meta.get(idx, {})

            if q.qtype == "single":
                display_options = meta["display_options"]
                val_disp = st.radio(
                    "",
                    options=list(range(len(display_options))),
                    format_func=lambda i: display_options[i],
                    index=None,
                    key=f"single_{idx}",
                    disabled=disabled,
                )
                st.session_state.answers[idx] = val_disp

            elif q.qtype == "multi":
                display_options = meta["display_options"]
                val_disp_list = st.multiselect(
                    "",
                    options=list(range(len(display_options))),
                    format_func=lambda i: display_options[i],
                    default=[],
                    key=f"multi_{idx}",
                    disabled=disabled,
                )
                st.session_state.answers[idx] = set(val_disp_list)

            elif q.qtype == "ordering":
                dropdown = meta["ordering_dropdown"]
                st.info("Choose the correct order from left (1) to right (last).")
                chosen = []
                cols = st.columns(len(q.options))
                for pos in range(len(q.options)):
                    with cols[pos]:
                        sel = st.selectbox(
                            f"{pos+1}",
                            options=dropdown,
                            index=None,
                            placeholder="Select...",
                            key=f"order_{idx}_{pos}",
                            disabled=disabled,
                        )
                    chosen.append(sel)
                st.session_state.answers[idx] = chosen

            if st.session_state.practice_mode:
                ans_disp = st.session_state.answers.get(idx)
                if q.qtype in ("single", "multi"):
                    d2o = meta["display_to_orig"]
                    if q.qtype == "single":
                        ans_orig = None if ans_disp is None else d2o[ans_disp]
                    else:
                        ans_orig = {d2o[i] for i in (ans_disp or set())}
                    pts = compute_points(q, ans_orig)
                else:
                    pts = compute_points(q, ans_disp)
                st.write(f"Points (now): **{pts}/{q.max_points}**")

            if st.session_state.show_facit and (st.session_state.practice_mode or st.session_state.submitted):
                st.caption(f"Facit: {facit_text(q)}")

        st.markdown("---")
        if st.button("✅ Grade & show results", type="primary"):
            st.session_state.submitted = True
            do_rerun()

        if st.session_state.submitted:
            results, cat_breakdown = grade_exam()

            total = sum(r["points"] for r in results)
            maxp = sum(r["max_points"] for r in results)
            st.success(f"**Total score: {total} / {maxp}**")

            st.markdown("## Category breakdown")
            rows = []
            for k, v in sorted(cat_breakdown.items(), key=lambda kv: kv[0].lower()):
                pct = 0.0 if v["max"] == 0 else round(100.0 * v["score"] / v["max"], 1)
                rows.append({"Category": k, "Score": v["score"], "Max": v["max"], "Percent": pct})
            st.dataframe(rows, use_container_width=True)

            st.markdown("## Review (Right/Wrong + What’s wrong)")
            for r in results:
                header = f"{r['qid']} — {'✅ Correct' if r['correct'] else '❌ Wrong'} ({r['points']}/{r['max_points']}) — [{r['category']}]"
                with st.expander(header, expanded=not r["correct"]):
                    st.write(r["question"])
                    st.write(f"**Your answer:** {r['your_answer']}")
                    st.write(f"**Correct:** {r['facit']}")
                    if not r["correct"]:
                        st.warning(r["details"])

            failed_count = sum(1 for r in results if not r["correct"])
            st.markdown("---")
            if failed_count > 0:
                st.info(f"You have {failed_count} failed question(s).")
                c1, c2 = st.columns([1, 2])

                with c1:
                    if st.button("🔁 Retry failed only"):
                        retry_failed_only(results)
                        do_rerun()

                with c2:
                    extra = st.number_input(
                        "Add extra random questions",
                        min_value=0,
                        max_value=len(bank),
                        value=min(5, len(bank)),
                        step=1,
                        help="New test = all failed + these extra random questions (from remaining bank).",
                    )
                    if st.button("🎯 Retry failed + random"):
                        retry_failed_plus_random(results, extra_random=int(extra))
                        do_rerun()
            else:
                st.success("🎉 All questions correct — nothing to retry!")


# ============================================================
# TAB 3: RESULTS HISTORY
# ============================================================

with tabs[2]:
    st.subheader("Results history (Google Drive)")

    results = load_results_for_user(user)
    if not results:
        st.info("No saved attempts yet. Take a test and grade it to save results.")
    else:
        results_sorted = list(reversed(results))
        st.write(f"Saved attempts: **{len(results_sorted)}**")

        table = []
        for a in results_sorted[:200]:
            table.append({
                "Time": a.get("timestamp"),
                "Questions": a.get("n_questions"),
                "Score": f"{a.get('total_score')}/{a.get('total_max')}",
                "Failed": len(a.get("failed_qids", [])),
            })
        st.dataframe(table, use_container_width=True)

        with st.expander("Show latest attempt details"):
            st.json(results_sorted[0])
