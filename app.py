"""
FitPlate - Workout and Nutrition Progress Companion (Streamlit MVP)

Run:  streamlit run app.py

Layers (Clean Architecture, in one file for simplicity):
  1. Data layer     - SQLite access (every query is filtered by the logged-in user's id)
  2. Auth           - registration + login with salted PBKDF2 password hashes
  3. Domain metrics - consistency, volume, change, energy comparison, reminders
  4. UI pages       - Dashboard, Workouts, Daily log, Charts

Educational tracking only. Not medical advice.
"""
import hashlib
import hmac
import html as _html
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import date, timedelta

import pandas as pd
import streamlit as st

# =============================================================================
# Configuration (formulas are kept simple and visible on purpose)
# =============================================================================
DB_PATH = os.environ.get("FITPLATE_DB", "fitplate.db")
CATEGORIES = ["Strength", "Cardio", "Yoga", "HIIT", "Mobility", "Sports", "Other"]
WEEKLY_TARGET_DAYS = 4      # consistency = workout days / 4 x 100 (max 100)
WATER_TARGET_ML = 2000      # general reference only, needs vary
INACTIVITY_DAYS = 3         # reminder if no workout for this many days
DISCLAIMER = ("FitPlate is for educational tracking only. It does not provide "
              "medical advice or diet prescriptions.")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# =============================================================================
# 1. DATA LAYER
# =============================================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,
    pw_hash TEXT NOT NULL,
    disclaimer_accepted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS workouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    date TEXT NOT NULL,
    category TEXT NOT NULL,
    exercise TEXT NOT NULL,
    sets INTEGER NOT NULL,
    reps INTEGER NOT NULL,
    weight REAL,
    duration_min INTEGER
);
CREATE TABLE IF NOT EXISTS habits (
    user_id INTEGER NOT NULL REFERENCES users(id),
    date TEXT NOT NULL,
    water_ml INTEGER NOT NULL DEFAULT 0,
    calories INTEGER,
    meal_note TEXT,
    energy INTEGER,
    PRIMARY KEY (user_id, date)
);
CREATE TABLE IF NOT EXISTS measurements (
    user_id INTEGER NOT NULL REFERENCES users(id),
    date TEXT NOT NULL,
    weight_kg REAL,
    waist_cm REAL,
    PRIMARY KEY (user_id, date)
);
CREATE INDEX IF NOT EXISTS idx_workouts_user_date ON workouts(user_id, date);
"""


def run(sql, params=(), fetch=False):
    """Run one SQL statement. Returns rows (list of dicts) if fetch=True."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            cur = conn.execute(sql, params)
            if fetch:
                return [dict(r) for r in cur.fetchall()]
            return cur.lastrowid


@st.cache_resource
def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            conn.executescript(SCHEMA)
    return True


def iso(d):
    return d.isoformat()


def get_workouts(uid, start, end):
    return run("SELECT * FROM workouts WHERE user_id=? AND date BETWEEN ? AND ? "
               "ORDER BY date DESC, id DESC", (uid, iso(start), iso(end)), fetch=True)


def get_habits(uid, start, end):
    return run("SELECT * FROM habits WHERE user_id=? AND date BETWEEN ? AND ? ORDER BY date",
               (uid, iso(start), iso(end)), fetch=True)


def get_measurements(uid, start, end):
    return run("SELECT * FROM measurements WHERE user_id=? AND date BETWEEN ? AND ? ORDER BY date",
               (uid, iso(start), iso(end)), fetch=True)


def add_workout(uid, d, category, exercise, sets, reps, weight, duration):
    run("INSERT INTO workouts (user_id,date,category,exercise,sets,reps,weight,duration_min) "
        "VALUES (?,?,?,?,?,?,?,?)", (uid, iso(d), category, exercise, sets, reps, weight, duration))


def delete_workout(uid, workout_id):
    run("DELETE FROM workouts WHERE id=? AND user_id=?", (workout_id, uid))


def add_water(uid, d, ml):
    run("INSERT INTO habits (user_id,date,water_ml) VALUES (?,?,?) "
        "ON CONFLICT(user_id,date) DO UPDATE SET water_ml = MIN(water_ml + excluded.water_ml, 10000)",
        (uid, iso(d), ml))


def save_habit(uid, d, calories, meal_note, energy):
    run("INSERT INTO habits (user_id,date,calories,meal_note,energy) VALUES (?,?,?,?,?) "
        "ON CONFLICT(user_id,date) DO UPDATE SET "
        "calories=COALESCE(excluded.calories, calories), "
        "meal_note=COALESCE(excluded.meal_note, meal_note), "
        "energy=COALESCE(excluded.energy, energy)",
        (uid, iso(d), calories, meal_note, energy))


def save_measurement(uid, d, weight_kg, waist_cm):
    run("INSERT INTO measurements (user_id,date,weight_kg,waist_cm) VALUES (?,?,?,?) "
        "ON CONFLICT(user_id,date) DO UPDATE SET "
        "weight_kg=COALESCE(excluded.weight_kg, weight_kg), "
        "waist_cm=COALESCE(excluded.waist_cm, waist_cm)",
        (uid, iso(d), weight_kg, waist_cm))


def count_rows(uid, table):
    """How many records this user has in a table (used for the welcome checklist)."""
    if table not in ("workouts", "habits", "measurements"):
        raise ValueError("unknown table")
    return run(f"SELECT COUNT(*) AS c FROM {table} WHERE user_id=?", (uid,), fetch=True)[0]["c"]


def set_water(uid, d, ml):
    run("INSERT INTO habits (user_id,date,water_ml) VALUES (?,?,?) "
        "ON CONFLICT(user_id,date) DO UPDATE SET water_ml=excluded.water_ml", (uid, iso(d), ml))


def clear_user_data(uid):
    """Delete everything this user logged (the account itself stays)."""
    for table in ("workouts", "habits", "measurements"):
        run(f"DELETE FROM {table} WHERE user_id=?", (uid,))


# =============================================================================
# 2. AUTHENTICATION
# =============================================================================
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def register_user(name, email, password, confirm):
    name, email = name.strip(), email.strip().lower()
    if not name:
        return False, "Please enter your name."
    if not EMAIL_RE.match(email):
        return False, "Please enter a valid email address."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if password != confirm:
        return False, "Passwords do not match."
    if run("SELECT id FROM users WHERE email=?", (email,), fetch=True):
        return False, "An account with this email already exists."
    salt = secrets.token_bytes(16)
    run("INSERT INTO users (name,email,salt,pw_hash) VALUES (?,?,?,?)",
        (name, email, salt, hash_password(password, salt)))
    return True, "Account created. You can log in now."


def login_user(email, password):
    rows = run("SELECT * FROM users WHERE email=?", (email.strip().lower(),), fetch=True)
    if not rows:
        return None
    u = rows[0]
    if not hmac.compare_digest(u["pw_hash"], hash_password(password, u["salt"])):
        return None
    return {"id": u["id"], "name": u["name"], "email": u["email"],
            "disclaimer": bool(u["disclaimer_accepted"])}


# =============================================================================
# 3. DOMAIN METRICS (pure functions, easy to unit test)
# =============================================================================
def workout_volume(w):
    """sets x reps x weight; bodyweight (no weight) -> sets x reps."""
    weight = w.get("weight") or 0
    return w["sets"] * w["reps"] * weight if weight > 0 else w["sets"] * w["reps"]


def consistency_pct(workout_days):
    return round(min(100.0, workout_days / WEEKLY_TARGET_DAYS * 100), 1)


def volume_change_pct(this_vol, last_vol):
    if not last_vol:
        return None
    return round((this_vol - last_vol) / last_vol * 100, 1)


def week_metrics(workouts, week_start):
    s, e = iso(week_start), iso(week_start + timedelta(days=6))
    items = [w for w in workouts if s <= w["date"] <= e]
    return {
        "count": len(items),
        "days": len({w["date"] for w in items}),
        "consistency": consistency_pct(len({w["date"] for w in items})),
        "volume": round(sum(workout_volume(w) for w in items), 1),
        "minutes": sum(w.get("duration_min") or 0 for w in items),
    }


def energy_comparison(workouts, habits):
    """Plain comparison of average energy on workout days vs rest days."""
    wdates = {w["date"] for w in workouts}
    on_w = [h["energy"] for h in habits if h.get("energy") and h["date"] in wdates]
    on_r = [h["energy"] for h in habits if h.get("energy") and h["date"] not in wdates]
    a = round(sum(on_w) / len(on_w), 2) if on_w else None
    b = round(sum(on_r) / len(on_r), 2) if on_r else None
    if a is None or b is None:
        msg = "Log energy on both workout and rest days to see a comparison."
    elif a > b:
        msg = "You reported higher energy on workout days."
    elif a < b:
        msg = "You reported higher energy on rest days."
    else:
        msg = "Your energy was about the same on workout and rest days."
    return a, b, msg


def build_reminders(today, workouts, habits):
    """Fixed, friendly, non-medical rules."""
    out = []
    past = sorted(w["date"] for w in workouts if w["date"] <= iso(today))
    if not past:
        out.append("No workouts logged yet. A short session today is a good start.")
    else:
        gap = (today - date.fromisoformat(past[-1])).days
        if gap >= INACTIVITY_DAYS:
            out.append(f"It has been {gap} days since your last workout. Time for a session?")
    todays = [h for h in habits if h["date"] == iso(today)]
    water = todays[0]["water_ml"] if todays else 0
    if water == 0:
        out.append("You have not logged any water today.")
    elif water < WATER_TARGET_ML:
        out.append(f"Water logged today: {water} ml. A common reference is about "
                   f"{WATER_TARGET_ML} ml, but needs vary from person to person.")
    return out


def monday_of(d):
    return d - timedelta(days=d.weekday())


# =============================================================================
# 4. UI
# =============================================================================
PAGES = [("Dashboard", "🏠"), ("Workouts", "🏋️"), ("Daily log", "💧"), ("Charts", "📈")]
THEME_TOML = '[theme]\nprimaryColor = "#16a34a"\n'

GLOBAL_CSS = """<style>
#MainMenu,footer{visibility:hidden;}
[data-testid="stAppDeployButton"]{display:none;}
.block-container{padding-top:2.2rem;max-width:1100px;}
.fp-hero{background:linear-gradient(135deg,#16a34a 0%,#0d9488 55%,#0ea5e9 100%);color:#fff;border-radius:18px;padding:26px 30px;margin-bottom:20px;}
.fp-hero-title{font-size:1.9rem;font-weight:800;line-height:1.2;}
.fp-hero-sub{opacity:.93;margin-top:6px;font-size:1rem;}
.fp-brand{font-size:1.5rem;font-weight:800;margin-bottom:2px;}
.fp-tag{font-size:.78rem;opacity:.65;margin-bottom:14px;}
.fp-user{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:12px;border:1px solid rgba(128,128,128,.28);background:rgba(128,128,128,.08);margin-bottom:16px;}
.fp-avatar{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#16a34a,#0d9488);color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;flex:none;}
.fp-uname{font-weight:600;line-height:1.2;}
.fp-umail{font-size:.75rem;opacity:.65;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:150px;}
.fp-card{border:1px solid rgba(128,128,128,.28);background:rgba(128,128,128,.08);border-radius:14px;padding:16px 18px;height:100%;}
.fp-label{font-size:.75rem;letter-spacing:.05em;text-transform:uppercase;opacity:.65;margin-bottom:6px;}
.fp-value{font-size:2rem;font-weight:700;line-height:1.1;}
.fp-sub{font-size:.85rem;opacity:.72;margin-top:6px;}
.fp-bar{height:8px;border-radius:99px;background:rgba(128,128,128,.25);margin-top:12px;overflow:hidden;}
.fp-bar>span{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,#16a34a,#0d9488);}
.fp-title{font-weight:600;font-size:1.05rem;margin-bottom:12px;}
.fp-days{display:flex;gap:8px;margin-bottom:18px;}
.fp-day{flex:1;text-align:center;font-size:.75rem;opacity:.9;}
.fp-dot{width:34px;height:34px;border-radius:50%;margin:0 auto 4px;border:2px solid rgba(128,128,128,.4);display:flex;align-items:center;justify-content:center;font-weight:700;}
.fp-dot.on{background:#16a34a;border-color:#16a34a;color:#fff;}
.fp-dot.today{border-color:#16a34a;}
.fp-row{display:flex;align-items:center;gap:10px;margin:10px 0;font-size:.85rem;}
.fp-row .name{width:95px;opacity:.75;}
.fp-row .track{flex:1;height:10px;border-radius:99px;background:rgba(128,128,128,.25);overflow:hidden;}
.fp-row .track>span{display:block;height:100%;border-radius:99px;background:#16a34a;}
.fp-row .track>span.alt{background:rgba(128,128,128,.7);}
.fp-row .val{width:70px;text-align:right;font-weight:600;}
.fp-remind{border-left:4px solid #f59e0b;background:rgba(245,158,11,.12);border-radius:10px;padding:10px 14px;margin-bottom:8px;font-size:.9rem;}
.fp-tip{border-left:4px solid #0ea5e9;background:rgba(14,165,233,.10);border-radius:10px;padding:10px 14px;margin-bottom:8px;font-size:.9rem;}
.fp-empty{border:2px dashed rgba(128,128,128,.35);border-radius:14px;padding:26px;text-align:center;margin:10px 0;}
.fp-empty .ico{font-size:2rem;}
.fp-empty .t{font-weight:600;margin-top:6px;}
.fp-empty .s{opacity:.7;font-size:.9rem;margin-top:4px;}
.fp-step{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,#16a34a,#0d9488);color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;margin-bottom:10px;}
.fp-feat .e{font-size:1.7rem;margin-bottom:6px;}
button[kind="primary"],button[data-testid="stBaseButton-primary"],button[data-testid="stBaseButton-primaryFormSubmit"]{background:linear-gradient(135deg,#16a34a,#0d9488)!important;border:none!important;color:#fff!important;}
[data-testid="stSidebar"] .stButton>button{width:100%;justify-content:flex-start;text-align:left;border-radius:10px;padding:.55rem .9rem;}
[data-testid="stSidebar"] button[data-testid="stBaseButton-secondary"]{background:transparent;border:1px solid transparent;}
[data-testid="stSidebar"] button[data-testid="stBaseButton-secondary"]:hover{background:rgba(128,128,128,.14);}
</style>"""


def ensure_theme_file():
    """Create .streamlit/config.toml once so sliders and bars use the green accent."""
    try:
        path = os.path.join(".streamlit", "config.toml")
        if not os.path.exists(path):
            os.makedirs(".streamlit", exist_ok=True)
            with open(path, "w") as f:
                f.write(THEME_TOML)
    except OSError:
        pass


def hero(title, subtitle=""):
    """Gradient banner. title/subtitle must already be HTML-safe."""
    st.markdown(f'<div class="fp-hero"><div class="fp-hero-title">{title}</div>'
                f'<div class="fp-hero-sub">{subtitle}</div></div>', unsafe_allow_html=True)


def empty_state(icon, title, text):
    st.markdown(f'<div class="fp-empty"><div class="ico">{icon}</div><div class="t">{title}</div>'
                f'<div class="s">{text}</div></div>', unsafe_allow_html=True)


def kpi_card(label, value, sub, pct=None):
    bar = ""
    if pct is not None:
        bar = f'<div class="fp-bar"><span style="width:{max(0, min(pct, 100)):.0f}%"></span></div>'
    return (f'<div class="fp-card"><div class="fp-label">{label}</div>'
            f'<div class="fp-value">{value}</div><div class="fp-sub">{sub}</div>{bar}</div>')


def bar_row(name, value, max_value, text, alt=False):
    pct = 0 if not max_value else min(value / max_value * 100, 100)
    cls = "alt" if alt else ""
    return (f'<div class="fp-row"><div class="name">{name}</div>'
            f'<div class="track"><span class="{cls}" style="width:{pct:.0f}%"></span></div>'
            f'<div class="val">{text}</div></div>')


def go(page):
    st.session_state["page"] = page
    st.rerun()


# ----------------------------------------------------------------------------- auth pages
def page_auth():
    hero("🏋️ FitPlate", "Connect everyday workouts with meaningful progress.")
    feats = [("🏋️", "Log workouts", "Strength, cardio, yoga and more, with sets, reps and weight."),
             ("💧", "Track daily habits", "Water, meals, energy and body measurements in one place."),
             ("📈", "See your progress", "Weekly consistency, training volume and clear charts.")]
    for col, (e, t, s) in zip(st.columns(3, gap="medium"), feats):
        col.markdown(f'<div class="fp-card fp-feat"><div class="e">{e}</div><div class="fp-title">{t}</div>'
                     f'<div class="fp-sub">{s}</div></div>', unsafe_allow_html=True)
    st.write("")

    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        tab_login, tab_reg = st.tabs(["Login", "Create account"])
        with tab_login:
            with st.form("login_form"):
                email = st.text_input("Email", key="login_email")
                password = st.text_input("Password", type="password", key="login_password")
                submitted = st.form_submit_button("Log in", type="primary")
            if submitted:
                user = login_user(email, password)
                if user:
                    st.session_state["user"] = user
                    st.rerun()
                else:
                    st.error("Incorrect email or password.")
        with tab_reg:
            with st.form("register_form"):
                name = st.text_input("Full name", key="reg_name")
                email = st.text_input("Email", key="reg_email")
                password = st.text_input("Password (min 8 characters)", type="password", key="reg_password")
                confirm = st.text_input("Confirm password", type="password", key="reg_confirm")
                submitted = st.form_submit_button("Create account", type="primary")
            if submitted:
                ok, msg = register_user(name, email, password, confirm)
                if ok:
                    st.success(msg + " Open the Login tab to sign in.")
                else:
                    st.error(msg)


def page_disclaimer(user):
    hero("Before you start", "One quick note about how FitPlate works.")
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.warning(DISCLAIMER)
        st.write("Reminders and insights are based only on what you enter. "
                 "Talk to a qualified professional for health decisions.")
        if st.button("I understand, let's start", type="primary"):
            run("UPDATE users SET disclaimer_accepted=1 WHERE id=?", (user["id"],))
            user["disclaimer"] = True
            st.rerun()


# ----------------------------------------------------------------------------- sidebar
def _clear_data_callback(uid):
    clear_user_data(uid)
    st.session_state["confirm_clear"] = False
    st.session_state["flash"] = "All your logged data was deleted."


def sidebar(user, uid):
    with st.sidebar:
        st.markdown('<div class="fp-brand">🏋️ FitPlate</div>'
                    '<div class="fp-tag">Workout and nutrition companion</div>', unsafe_allow_html=True)
        initial = _html.escape((user["name"].strip()[:1] or "?").upper())
        st.markdown(f'<div class="fp-user"><div class="fp-avatar">{initial}</div><div>'
                    f'<div class="fp-uname">{_html.escape(user["name"])}</div>'
                    f'<div class="fp-umail">{_html.escape(user["email"])}</div></div></div>',
                    unsafe_allow_html=True)
        current = st.session_state.get("page", "Dashboard")
        for label, icon in PAGES:
            if st.button(f"{icon}  {label}", key=f"nav_{label}",
                         type="primary" if label == current else "secondary"):
                go(label)
        st.divider()
        with st.expander("Account"):
            st.write("Delete everything you have logged (workouts, daily logs, measurements). "
                     "Your account stays.")
            confirm = st.checkbox("Yes, delete my data", key="confirm_clear")
            st.button("Delete my data", key="btn_clear", disabled=not confirm,
                      on_click=_clear_data_callback, args=(uid,))
        if st.button("↩  Log out", key="btn_logout"):
            st.session_state.clear()
            st.rerun()


# ----------------------------------------------------------------------------- dashboard
def onboarding(user):
    first = _html.escape(user["name"].split()[0])
    hero(f"Welcome, {first} 🎉", "Let's set up your first week. It takes about two minutes.")
    steps = [
        ("1", "Log your first workout", "Pick a category, add sets and reps. This unlocks your weekly "
                                         "consistency and training volume.", "Open Workouts", "Workouts"),
        ("2", "Add today's water and energy", "Tap +250 ml when you drink and rate your energy from 1 to 5.",
         "Open Daily log", "Daily log"),
        ("3", "Record a body measurement", "Add your weight or waist. Two entries on different days "
                                           "unlock the trend charts.", "Open Daily log", "Daily log"),
    ]
    for col, (n, title, text, btn, page) in zip(st.columns(3, gap="medium"), steps):
        with col:
            st.markdown(f'<div class="fp-card"><div class="fp-step">{n}</div>'
                        f'<div class="fp-title">{title}</div><div class="fp-sub">{text}</div></div>',
                        unsafe_allow_html=True)
            if st.button(btn + " →", key=f"ob_{n}"):
                go(page)
    st.write("")
    with st.expander("How FitPlate scores your week"):
        st.markdown(
            f"- **Consistency** = workout days / {WEEKLY_TARGET_DAYS} x 100 (max 100)\n"
            "- **Training volume** = sets x reps x weight (sets x reps if no weight)\n"
            "- **Reminders** are simple rules, like no workout for 3 days or low water\n"
            "- **Energy** compares your average energy on workout days and rest days")
    st.caption(DISCLAIMER)


def page_dashboard(uid):
    user = st.session_state["user"]
    counts = {t: count_rows(uid, t) for t in ("workouts", "habits", "measurements")}
    if sum(counts.values()) == 0:
        onboarding(user)
        return

    today = date.today()
    this_start = monday_of(today)
    last_start = this_start - timedelta(days=7)
    window_end = this_start + timedelta(days=6)

    workouts = get_workouts(uid, last_start, window_end)
    habits = get_habits(uid, last_start, window_end)
    this_w = week_metrics(workouts, this_start)
    last_w = week_metrics(workouts, last_start)
    change = volume_change_pct(this_w["volume"], last_w["volume"])
    reminders = build_reminders(today, workouts, habits)
    a, b, energy_msg = energy_comparison(workouts, habits)

    todays = [h for h in habits if h["date"] == iso(today)]
    water_today = todays[0]["water_ml"] if todays else 0
    water_vals = [h["water_ml"] for h in habits if h["date"] >= iso(this_start) and h["water_ml"] > 0]
    avg_water = round(sum(water_vals) / len(water_vals)) if water_vals else 0

    first = _html.escape(user["name"].split()[0])
    hero(f"Hi, {first} 👋", today.strftime("%A, %d %B %Y") + " · here is your week at a glance")

    if reminders:
        st.markdown("".join(f'<div class="fp-remind">{_html.escape(r)}</div>' for r in reminders),
                    unsafe_allow_html=True)
    tips = []
    if counts["workouts"] == 0:
        tips.append("Next step: log your first workout in Workouts to unlock consistency and volume.")
    if counts["measurements"] < 2:
        tips.append("Add weight on two different days in Daily log to unlock the weight chart.")
    if tips:
        st.markdown("".join(f'<div class="fp-tip">{_html.escape(t)}</div>' for t in tips),
                    unsafe_allow_html=True)

    if change is None:
        vol_sub = "No data from last week yet"
    else:
        vol_sub = f'{"▲" if change >= 0 else "▼"} {abs(change):.0f}% vs last week'
    k1, k2, k3, k4 = st.columns(4, gap="medium")
    k1.markdown(kpi_card("Consistency", f"{this_w['consistency']:.0f}%",
                         f"{this_w['days']} of {WEEKLY_TARGET_DAYS} workout days",
                         this_w["consistency"]), unsafe_allow_html=True)
    k2.markdown(kpi_card("Training volume", f"{this_w['volume']:,.0f}", vol_sub), unsafe_allow_html=True)
    k3.markdown(kpi_card("Active time", f"{this_w['minutes']} min",
                         f"{this_w['count']} workout{'s' if this_w['count'] != 1 else ''} this week"),
                unsafe_allow_html=True)
    k4.markdown(kpi_card("Water today", f"{water_today} ml", f"Reference ~{WATER_TARGET_ML} ml",
                         water_today / WATER_TARGET_ML * 100), unsafe_allow_html=True)
    st.write("")

    wdates = {w["date"] for w in workouts}
    names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    cells = ""
    for i in range(7):
        d = this_start + timedelta(days=i)
        on = iso(d) in wdates
        cls = "fp-dot" + (" on" if on else "") + (" today" if d == today else "")
        cells += f'<div class="fp-day"><div class="{cls}">{"✓" if on else ""}</div>{names[i]}</div>'
    mx = max(this_w["volume"], last_w["volume"], 1)
    left = ('<div class="fp-card"><div class="fp-title">Your week</div>'
            f'<div class="fp-days">{cells}</div>'
            '<div class="fp-label">Training volume</div>'
            + bar_row("This week", this_w["volume"], mx, f"{this_w['volume']:,.0f}")
            + bar_row("Last week", last_w["volume"], mx, f"{last_w['volume']:,.0f}", alt=True)
            + '</div>')
    right = ('<div class="fp-card"><div class="fp-title">Energy and hydration</div>'
             '<div class="fp-label">Average energy (1-5)</div>'
             + bar_row("Workout days", a or 0, 5, f"{a}" if a is not None else "-")
             + bar_row("Rest days", b or 0, 5, f"{b}" if b is not None else "-", alt=True)
             + f'<div class="fp-sub">{_html.escape(energy_msg)}</div>'
             '<div class="fp-label" style="margin-top:18px">Average water this week</div>'
             + bar_row("Per day", avg_water, WATER_TARGET_ML, f"{avg_water} ml")
             + '</div>')
    c1, c2 = st.columns([3, 2], gap="medium")
    c1.markdown(left, unsafe_allow_html=True)
    c2.markdown(right, unsafe_allow_html=True)

    st.write("")
    with st.expander("How scores are calculated"):
        st.markdown(
            f"- **Consistency** = workout days / {WEEKLY_TARGET_DAYS} x 100 (max 100)\n"
            "- **Training volume** = sets x reps x weight (sets x reps if no weight)\n"
            "- **Change** = (this week - last week) / last week x 100\n"
            "- **Energy** = average energy on workout days vs rest days, from the last two weeks "
            "of your own entries (a simple comparison, not a statistical correlation)")
    st.caption(DISCLAIMER)


# ----------------------------------------------------------------------------- workouts
def page_workouts(uid):
    hero("Workouts", "Log what you did. Your weekly score and volume update automatically.")
    with st.form("workout_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        category = c1.selectbox("Category", CATEGORIES)
        d = c2.date_input("Date", value=date.today(), max_value=date.today())
        exercise = st.text_input("Exercise", max_chars=60, placeholder="e.g. Bench press, Running, Sun salutation")
        c3, c4, c5, c6 = st.columns(4)
        sets = c3.number_input("Sets", 1, 50, 3)
        reps = c4.number_input("Reps", 1, 200, 10)
        weight = c5.number_input("Weight kg (0 = bodyweight)", 0.0, 1000.0, 0.0, step=2.5)
        duration = c6.number_input("Minutes (0 = skip)", 0, 600, 0)
        saved = st.form_submit_button("Save workout", type="primary")
    if saved:
        if not exercise.strip():
            st.error("Please enter an exercise name.")
        else:
            add_workout(uid, d, category, exercise.strip(), int(sets), int(reps),
                        float(weight) if weight > 0 else None, int(duration) if duration > 0 else None)
            st.success("Workout saved.")
            st.rerun()

    rows = get_workouts(uid, date.today() - timedelta(days=120), date.today())
    st.subheader("History")
    if not rows:
        empty_state("🏋️", "No workouts yet", "Fill in the form above and tap Save workout to log your first one.")
        return
    df = pd.DataFrame(rows)[["date", "category", "exercise", "sets", "reps", "weight", "duration_min"]]
    df.columns = ["Date", "Category", "Exercise", "Sets", "Reps", "Weight (kg)", "Minutes"]
    st.dataframe(df, hide_index=True)
    st.caption("Showing the last 120 days.")

    with st.expander("Delete a workout"):
        labels = {f"{r['date']} · {r['exercise']} ({r['sets']}x{r['reps']})": r["id"] for r in rows}
        choice = st.selectbox("Choose workout", list(labels))
        if st.button("Delete this workout"):
            delete_workout(uid, labels[choice])
            st.rerun()


# ----------------------------------------------------------------------------- daily log
def page_today(uid):
    hero("Daily log", "Water, meals, energy and body measurements for the day you pick.")
    d = st.date_input("Date", value=date.today(), max_value=date.today(), key="today_date")
    habit = (get_habits(uid, d, d) or [None])[0]
    water = habit["water_ml"] if habit else 0

    left, right = st.columns(2, gap="medium")
    with left:
        with st.container(border=True):
            st.subheader("💧 Water")
            st.metric("Logged", f"{water} ml")
            st.progress(min(water / WATER_TARGET_ML, 1.0))
            b1, b2, b3 = st.columns(3)
            if b1.button("+250 ml", type="primary"):
                add_water(uid, d, 250)
                st.rerun()
            if b2.button("+500 ml"):
                add_water(uid, d, 500)
                st.rerun()
            if b3.button("Reset", help="Set this day's water back to 0"):
                set_water(uid, d, 0)
                st.rerun()
    with right:
        with st.container(border=True):
            st.subheader("🍽️ Meals and energy")
            with st.form("habit_form"):
                calories = st.number_input("Calories (estimate, 0 = skip)", 0, 10000,
                                           int(habit["calories"] or 0) if habit else 0, step=50)
                meal = st.text_input("Meal note", max_chars=200,
                                     value=(habit["meal_note"] or "") if habit else "")
                energy = st.slider("Energy level (1 = low, 5 = high)", 1, 5,
                                   int(habit["energy"]) if habit and habit["energy"] else 3)
                if st.form_submit_button("Save daily log", type="primary"):
                    save_habit(uid, d, int(calories) if calories > 0 else None,
                               meal.strip() or None, int(energy))
                    st.success("Saved.")
                    st.rerun()

    with st.container(border=True):
        st.subheader("📏 Body measurements")
        with st.form("measure_form"):
            c1, c2 = st.columns(2)
            weight = c1.number_input("Weight kg (0 = skip)", 0.0, 400.0, 0.0, step=0.1)
            waist = c2.number_input("Waist cm (0 = skip)", 0.0, 250.0, 0.0, step=0.5)
            if st.form_submit_button("Save measurement", type="primary"):
                bad = (0 < weight < 20) or (0 < waist < 30)
                if weight == 0 and waist == 0:
                    st.error("Enter weight or waist.")
                elif bad:
                    st.error("Check your values (weight 20-400 kg, waist 30-250 cm).")
                else:
                    save_measurement(uid, d, float(weight) if weight else None,
                                     float(waist) if waist else None)
                    st.success("Measurement saved.")
                    st.rerun()


# ----------------------------------------------------------------------------- charts
def _trend_chart(title, rows, key, label):
    st.subheader(title)
    pts = [(r["date"], r[key]) for r in rows if r[key] is not None]
    if len(pts) >= 2:
        df = pd.DataFrame(pts, columns=["date", label])
        df["date"] = pd.to_datetime(df["date"])
        st.line_chart(df.set_index("date"), height=240, color="#16a34a")
    else:
        empty_state("📏", "Not enough data yet",
                    f"Log {label.lower()} on at least two different days in Daily log.")


def page_charts(uid):
    hero("Progress charts", "See how your body measurements, training and hydration are trending.")
    days = st.radio("Range", [7, 30, 90], index=1, horizontal=True, format_func=lambda x: f"Last {x} days")
    today = date.today()
    start = today - timedelta(days=days)
    meas = get_measurements(uid, start, today)

    c1, c2 = st.columns(2, gap="large")
    with c1:
        _trend_chart("Weight (kg)", meas, "weight_kg", "Weight (kg)")
    with c2:
        _trend_chart("Waist (cm)", meas, "waist_cm", "Waist (cm)")

    c3, c4 = st.columns(2, gap="large")
    with c3:
        st.subheader("Weekly training volume")
        this_start = monday_of(today)
        all_w = get_workouts(uid, this_start - timedelta(days=35), this_start + timedelta(days=6))
        vols = {iso(this_start - timedelta(days=7 * k)):
                week_metrics(all_w, this_start - timedelta(days=7 * k))["volume"] for k in range(5, -1, -1)}
        if any(vols.values()):
            st.bar_chart(pd.DataFrame({"Volume": vols}), height=240, color="#16a34a")
            st.caption("Last 6 weeks. Each bar is labelled by its Monday.")
        else:
            empty_state("🏋️", "No workouts in the last 6 weeks", "Log a workout and your weekly volume appears here.")
    with c4:
        st.subheader("Water (ml per day)")
        hab = [h for h in get_habits(uid, start, today) if h["water_ml"] > 0]
        if hab:
            df = pd.DataFrame([(h["date"], h["water_ml"]) for h in hab], columns=["date", "Water (ml)"])
            df["date"] = pd.to_datetime(df["date"])
            st.bar_chart(df.set_index("date"), height=240, color="#0d9488")
        else:
            empty_state("💧", "No water logged in this range", "Tap +250 ml in Daily log whenever you drink.")


# ----------------------------------------------------------------------------- main
def main():
    st.set_page_config(page_title="FitPlate", page_icon="🏋️", layout="wide")
    ensure_theme_file()
    init_db()
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

    user = st.session_state.get("user")
    if not user:
        page_auth()
        return
    if not user["disclaimer"]:
        page_disclaimer(user)
        return

    uid = user["id"]
    sidebar(user, uid)
    flash = st.session_state.pop("flash", None)
    if flash:
        st.success(flash)

    pages = {"Dashboard": page_dashboard, "Workouts": page_workouts,
             "Daily log": page_today, "Charts": page_charts}
    pages[st.session_state.get("page", "Dashboard")](uid)


main()
