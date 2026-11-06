"""qsafe-certs web app.

Run:  streamlit run app.py
"""
import json
from datetime import date

import streamlit as st

from qsafe.certificate import Certificate
from qsafe.qkd import QBER_THRESHOLD, decrypt, encrypt, establish_hybrid_channel, run_bb84
from qsafe.registry import HASH_ALGORITHMS, TSA_ALGORITHMS, TSA_NAMES, UNIVERSITY, Registry

st.set_page_config(page_title="qsafe-certs", page_icon="🎓", layout="centered")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,500;8..60,600&display=swap');
html, body, [class*="st-"], .stMarkdown { font-family: 'IBM Plex Sans', 'Segoe UI', system-ui, sans-serif; }
h1, h2, h3 { font-family: 'Source Serif 4', Georgia, 'Times New Roman', serif !important; color: #1B2733; letter-spacing: -0.01em; }
.verdict { border-left: 6px solid var(--c); padding: 0.9rem 1.2rem; margin: 1rem 0 0.6rem; background: #FFFFFF; }
.verdict .word { font-family: 'Source Serif 4', Georgia, serif; font-size: 2.4rem; font-weight: 600; color: var(--c); line-height: 1.1; }
.verdict .sub { color: #4A5966; margin-top: 0.25rem; }
.chain { border-left: 2px solid #C9D2DA; margin: 0.4rem 0 1rem 0.5rem; padding-left: 1.1rem; }
.stamp { position: relative; margin: 0 0 0.8rem; }
.stamp::before { content: ""; position: absolute; left: -1.53rem; top: 0.35rem; width: 0.7rem; height: 0.7rem;
                 border-radius: 50%; background: var(--c); border: 2px solid #FFFFFF; }
.stamp .when { font-weight: 600; color: #1B2733; }
.stamp .what { color: #4A5966; font-size: 0.92rem; }
.cert { border: 1px solid #C9D2DA; padding: 1.2rem 1.4rem; background: #FFFFFF; }
.cert .inst { font-family: 'Source Serif 4', Georgia, serif; font-size: 1.25rem; font-weight: 600; color: #23466B; }
.cert .holder { font-family: 'Source Serif 4', Georgia, serif; font-size: 1.6rem; margin: 0.6rem 0 0.2rem; }
.cert .meta { color: #4A5966; font-size: 0.92rem; }
</style>
""", unsafe_allow_html=True)

GREEN, RED = "#22704A", "#A8322A"


@st.cache_resource
def get_registry() -> Registry:
    return Registry()


reg = get_registry()

BREAK_DEFAULTS = {"ECDSA-P256": date(2045, 3, 1), "ML-DSA-65": date(2052, 1, 1), "SLH-DSA-SHA2-128s": date(2065, 1, 1)}

# Streamlit reruns this script top to bottom on every interaction, and the Verify tab is
# drawn before Simulate the future. So every change to the world (algorithm breaks,
# renewals) is applied HERE, before anything is drawn, or in a button callback, which
# Streamlit runs before the rerun. Otherwise Verify would show results one step behind.
for _alg, _default in BREAK_DEFAULTS.items():
    if f"brk-{_alg}" in st.session_state:
        reg.set_broken(_alg, st.session_state.get(f"when-{_alg}", _default) if st.session_state[f"brk-{_alg}"] else None)
if "tsa-threshold" in st.session_state:
    reg.set_threshold(st.session_state["tsa-threshold"])


def restore_upload(box: str, original: str) -> None:
    st.session_state[box] = original


def do_renew() -> None:
    try:
        auths = st.session_state.get("renew-auths", TSA_NAMES)
        n = reg.renew(st.session_state["renew-tsa"], st.session_state["renew-hash"], st.session_state["renew-date"],
                      auths)
        msg = (f"Renewed {n} record{'' if n == 1 else 's'} with one joint {st.session_state['renew-tsa']} "
               f"timestamp from {len(auths)} authorit{'y' if len(auths) == 1 else 'ies'}.")
        refused = reg.last_refused
        if refused:
            msg += (f" Refused {len(refused)} record{'' if len(refused) == 1 else 's'} whose evidence was already "
                    f"invalid on the renewal date: " + "; ".join(f"{cid} ({why})" for cid, why in refused.items()))
            st.session_state["renew-msg"] = ("warning" if n else "error", msg)
        else:
            st.session_state["renew-msg"] = ("success", msg)
    except ValueError as e:
        st.session_state["renew-msg"] = ("error", str(e))


def cert_card(cert: Certificate) -> None:
    c = cert.content
    algs = ", ".join(s.algorithm for s in cert.signatures)
    st.markdown(f"""<div class="cert"><div class="inst">{cert.issuer}</div>
        <div class="holder">{c.get('name', '')}</div>
        <div>{c.get('degree', '')}, CGPA {c.get('cgpa', '')}, class of {c.get('year', '')}</div>
        <div class="meta">Certificate {cert.certificate_id}, issued {cert.issued_on}. Signed with {algs}.</div>
        </div>""", unsafe_allow_html=True)


def download(cert: Certificate, label: str = "Download certificate file") -> None:
    st.download_button(label, json.dumps(cert.to_dict(), indent=2), file_name=f"{cert.certificate_id}.json",
                       mime="application/json", key=f"dl-{cert.certificate_id}-{label}")


def show_result(cert: Certificate, as_of: date, record=None) -> None:
    """`record` is evidence presented with the certificate; otherwise the archive's record is used."""
    result, notes = reg.verify(cert, as_of, record)
    colour = GREEN if result.genuine else RED
    word = "Genuine" if result.genuine else "Rejected"
    sub = ("This certificate is authentic as of " if result.genuine
           else "This certificate cannot be trusted as of ") + as_of.strftime("%d %B %Y") + "."
    st.markdown(f'<div class="verdict" style="--c:{colour}"><div class="word">{word}</div>'
                f'<div class="sub">{sub}</div></div>', unsafe_allow_html=True)
    st.markdown("**Why**")
    for r in result.reasons:
        st.markdown(f"- {r}")
    presented = record is not None
    record = record or reg.record_for(cert)
    if record and record.links:
        st.markdown("**Evidence presented with the certificate**" if presented
                    else "**Evidence chain held by the national archive**")
        items = []
        for i, link in enumerate(record.links):
            ts = link.timestamp
            ok = i < len(notes) and notes[i].endswith(" ok")
            items.append(f'<div class="stamp" style="--c:{GREEN if ok else RED}"><div class="when">{ts.time}</div>'
                         f'<div class="what">Signed by {len(ts.signatures)} of {len(TSA_NAMES)} authorities'
                         f'{" (" + ", ".join(ts.authorities) + ")" if ts.signatures else ""} using '
                         f'{", ".join(ts.algorithms) or "no algorithm"} and {ts.hash_alg}'
                         f'{"" if ok else " (not valid)"}</div></div>')
        st.markdown('<div class="chain">' + "".join(items) + "</div>", unsafe_allow_html=True)
    elif record is None:
        st.caption("The national archive holds no record of this certificate.")


st.title("Quantum-safe certificates")
st.write(f"Issue degrees from {UNIVERSITY}, verify them, and see whether they survive future quantum attacks.")

tab_issue, tab_verify, tab_future, tab_keys = st.tabs(["Issue", "Verify", "Simulate the future", "Key transfer"])

# ------------------------------------------------------------------ Issue ---
with tab_issue:
    st.subheader("Issue a degree certificate")
    st.write("The university signs with ECDSA and ML-DSA, and three independent timestamp authorities "
             "jointly timestamp it the same day.")
    with st.form("issue"):
        name = st.text_input("Student name", "A. Kumar")
        degree = st.selectbox("Degree", ["B.Tech CSE", "B.Tech ECE", "M.Tech AI", "MBA", "Ph.D. Physics"])
        col1, col2 = st.columns(2)
        cgpa = col1.number_input("CGPA", 0.0, 10.0, 8.7, 0.01, format="%.2f")
        issued_on = col2.date_input("Issue date", date(2026, 6, 1), min_value=date(2020, 1, 1),
                                    max_value=date(2070, 12, 31))
        submitted = st.form_submit_button("Issue certificate", type="primary")
    if submitted:
        if not name.strip():
            st.error("Enter the student's name to issue a certificate.")
        else:
            cert = reg.issue(name.strip(), degree, f"{cgpa:.2f}", issued_on.year, issued_on)
            st.session_state["last_issued"] = cert.certificate_id
            st.success(f"Issued certificate {cert.certificate_id}.")
    if "last_issued" in st.session_state and st.session_state["last_issued"] in reg.issued:
        cert = reg.issued[st.session_state["last_issued"]]
        cert_card(cert)
        download(cert)

# ----------------------------------------------------------------- Verify ---
with tab_verify:
    st.subheader("Verify a certificate")
    source = st.radio("Certificate to check", ["Upload a certificate file", "Choose an issued certificate"],
                      horizontal=True)
    cert = None
    if source == "Upload a certificate file":
        up = st.file_uploader("Certificate file (.json)", type="json")
        if up is not None:
            original = up.getvalue().decode()
            # One text box per upload, so a fresh upload always shows the file exactly as it is.
            box = f"edit-{up.file_id}"
            if box not in st.session_state:
                st.session_state[box] = original
            raw = st.text_area("Certificate contents. Edit any value to test tamper detection.", key=box, height=220)
            if raw != original:
                st.warning("You've edited this certificate, so it no longer matches the uploaded file. "
                           "The file on your computer is unchanged.")
                st.button("Restore original file", on_click=restore_upload, args=(box, original))
            try:
                cert = Certificate.from_dict(json.loads(raw))
            except Exception:
                st.error("This file isn't a valid certificate. Upload a .json file downloaded from the Issue tab.")
    elif reg.issued:
        cid = st.selectbox("Issued certificate", list(reg.issued))
        cert = reg.issued[cid]
    else:
        st.info("No certificates issued yet. Issue one in the Issue tab first.")
    as_of = st.date_input("Check as of", date.today(), key="verify-asof", min_value=date(2020, 1, 1), max_value=date(2070, 12, 31),
                          help="Pick a future date to see how the certificate holds up after algorithm breaks.")
    if cert is not None:
        cert_card(cert)
        show_result(cert, as_of)

# ---------------------------------------------------- Simulate the future ---
with tab_future:
    st.subheader("Algorithm breaks")
    st.write("Mark an algorithm as broken from a given date, as if a quantum computer or new attack defeats it.")
    for alg, default in BREAK_DEFAULTS.items():
        c1, c2 = st.columns([1, 1])
        broken = c1.checkbox(f"{alg} broken", value=alg in reg.policy.broken_at, key=f"brk-{alg}")
        when = c2.date_input(f"Broken from ({alg})", reg.policy.broken_at.get(alg, default),
                             min_value=date(2020, 1, 1), max_value=date(2070, 12, 31), key=f"when-{alg}",
                             disabled=not broken, label_visibility="collapsed")

    st.subheader("Timestamp authorities")
    st.write("Three independent authorities sign every timestamp: " + ", ".join(TSA_NAMES) + ". "
             "Choose how many must agree. With one, a single stolen key or dishonest authority can backdate "
             "a forgery; with two, an attacker must control two authorities.")
    st.radio("Authorities required per timestamp", [1, 2, 3], index=reg.policy.tsa_threshold - 1,
             key="tsa-threshold", horizontal=True, format_func=lambda k: f"{k} of {len(TSA_NAMES)}")

    st.subheader("Renew the archive")
    st.write("Re-timestamp every record with a stronger algorithm before the current one breaks. "
             "Only fingerprints are renewed, so no certificate can be changed.")
    c1, c2, c3 = st.columns(3)
    c1.selectbox("Timestamp algorithm", TSA_ALGORITHMS, index=1, key="renew-tsa")
    c2.selectbox("Hash", HASH_ALGORITHMS, index=1, key="renew-hash")
    c3.date_input("Renewal date", date(2040, 1, 15), min_value=date(2020, 1, 1),
                  max_value=date(2070, 12, 31), key="renew-date")
    st.multiselect("Authorities taking part", TSA_NAMES, default=TSA_NAMES, key="renew-auths")
    st.button("Renew archive", disabled=not reg.archive.certs, on_click=do_renew)
    if "renew-msg" in st.session_state:
        kind, msg = st.session_state.pop("renew-msg")
        {"success": st.success, "warning": st.warning}.get(kind, st.error)(msg)
    if not reg.archive.certs:
        st.caption("Issue at least one certificate before renewing the archive.")
    if reg.renewals:
        st.table([{"Date": d.isoformat(), "Algorithm": a, "Hash": h, "Authorities": len(auths), "Records": n}
                  for d, a, h, auths, n in reg.renewals])

    st.subheader("Try a forgery")
    st.write("An attacker who has broken ECDSA derives the university's private key and signs a fake, "
             "backdated degree. If they also control some timestamp authorities (stolen keys or dishonest "
             "insiders), those authorities give the forgery a backdated timestamp.")
    c1, c2, c3 = st.columns(3)
    f_name = c1.text_input("Fake name", "M. Fraud")
    f_cgpa = c2.text_input("Fake CGPA", "9.80")
    f_date = c3.date_input("Claimed issue date", date(2026, 6, 1), min_value=date(2020, 1, 1),
                           max_value=date(2070, 12, 31))
    f_check = st.date_input("Verify the forgery as of", date(2045, 6, 1), min_value=date(2020, 1, 1),
                            max_value=date(2070, 12, 31))
    compromised = st.multiselect("Timestamp authorities the attacker controls", TSA_NAMES, key="forge-tsas")
    if st.button("Forge certificate"):
        if compromised:
            fc, frec = reg.forge_with_authorities(f_name, f_cgpa, f_date, compromised)
        else:
            fc, frec = reg.forge(f_name, f_cgpa, f_date), None
        st.session_state["forged"] = (fc.to_dict(), frec)
    if "forged" in st.session_state:
        fdict, frec = st.session_state["forged"]
        forged = Certificate.from_dict(fdict)
        cert_card(forged)
        show_result(forged, f_check, frec)
        download(forged, "Download forged file")

# ----------------------------------------------------------- Key transfer ---
with tab_keys:
    st.subheader("Move signing keys between offices")
    st.write("Simulated BB84 quantum key distribution detects eavesdroppers through the error rate. "
             "The final key combines BB84 with ML-KEM, so an attacker must break both.")
    eve = st.slider("Share of photons the eavesdropper intercepts", 0, 100, 0, 5, format="%d%%")
    if st.button("Run key exchange", type="primary"):
        bb84 = run_bb84(eavesdrop_fraction=eve / 100)
        c1, c2, c3 = st.columns(3)
        c1.metric("Error rate (QBER)", f"{bb84.qber:.1%}", help=f"Abort threshold {QBER_THRESHOLD:.0%}")
        c2.metric("Sifted bits", bb84.sifted_bits)
        c3.metric("Photons sent", bb84.photons_sent)
        if bb84.key is None:
            st.error(f"Eavesdropper detected: the error rate is above {QBER_THRESHOLD:.0%}. "
                     "The key was discarded and nothing was sent.")
        else:
            key_a, key_b, _ = establish_hybrid_channel(bb84=bb84)
            payload = b"encrypted backup of the university signing keys"
            ok = key_a is not None and decrypt(key_b, encrypt(key_a, payload)) == payload
            st.success("No eavesdropper detected. Hybrid BB84 + ML-KEM key agreed and the key backup "
                       "was sent and decrypted." if ok else "Key exchange failed; nothing was sent.")
            if eve:
                st.caption("Light interception can stay under the threshold. A real system shortens the key "
                           "according to the measured error rate to remove what the eavesdropper learned; "
                           "this simulation simplifies that step.")

st.divider()
if st.button("Start over with a fresh university and archive"):
    get_registry.clear()
    st.session_state.clear()
    st.rerun()
st.caption("Prototype for research. Keys live in memory and reset when the app restarts. "
           "Do not use for real certificates.")
