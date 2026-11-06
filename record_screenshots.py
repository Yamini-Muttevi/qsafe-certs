"""Click through every test scenario in the running web app and save screenshots.

Start the app first:  python -m streamlit run app.py
Then, in a second terminal:  pip install playwright && python -m playwright install chromium
                             python record_screenshots.py
Screenshots go to ./screenshots/.
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

URL = os.environ.get("APP_URL", "http://localhost:8501")
OUT = "screenshots"
os.makedirs(OUT, exist_ok=True)
log = []


def idle(pg, extra=600):
    """Wait for Streamlit to finish rerunning."""
    pg.wait_for_timeout(400)
    status = pg.locator('[data-testid="stStatusWidget"]')
    try:
        status.wait_for(state="hidden", timeout=60000)
    except Exception:
        pass
    pg.wait_for_timeout(extra)


def tab(pg, name):
    pg.get_by_role("tab", name=name).click()
    idle(pg)


def set_date(pg, label, value):
    """Streamlit's date box has separate year, month and day fields; type into each."""
    widget = pg.locator('[data-testid="stDateInput"]').filter(has_text=label)
    segments = widget.get_by_role("spinbutton")
    for i, part in enumerate(value.split("/")):
        segments.nth(i).click()
        segments.nth(i).type(part)
    pg.get_by_text("Quantum-safe certificates", exact=True).click()  # clicking away commits the date
    idle(pg, 1500)
    shown = widget.inner_text().replace(" ", "").replace("\n", "")
    assert value.replace("/", "") in shown.replace("/", ""), f"date not set: {shown}"


def tick(pg, label):
    box = pg.get_by_role("checkbox", name=label)
    for _ in range(4):  # a click can be lost if it lands while Streamlit is still rerunning
        if box.is_checked():
            return
        pg.locator('[data-testid="stCheckbox"]').filter(has_text=label).locator("label").click()
        idle(pg, 1500)
    assert box.is_checked(), f"could not tick {label}"


def multiselect(pg, label, options):
    widget = pg.locator('[data-testid="stMultiSelect"]').filter(has_text=label)
    # clear existing choices
    clear = widget.locator('[aria-label="Clear all"], [title="Clear all"]')
    if clear.count():
        clear.first.click()
        idle(pg)
    for opt in options:
        widget.locator("input").click()
        pg.get_by_role("option", name=opt).click()
        idle(pg)
    pg.keyboard.press("Escape")
    idle(pg)


def shot(pg, name, caption, start_text=None, height=1100, expected="-"):
    """Full-page screenshot, or a crop starting at the heading `start_text`."""
    path = f"{OUT}/{name}.png"
    if start_text:
        top = pg.get_by_text(start_text, exact=True).first.bounding_box()["y"] - 20
        pg.screenshot(path=path, full_page=True,
                      clip={"x": 150, "y": max(top, 0), "width": 800, "height": height})
    else:
        pg.screenshot(path=path, full_page=True)
    panel = pg.locator('[role="tabpanel"]:not([hidden])')
    verdicts = [v.inner_text().split("\n")[0] for v in panel.locator(".verdict").all()]
    actual = verdicts[-1] if verdicts else "-"
    log.append((name, caption, expected, actual))
    print(f"{name}: {caption} -> expected {expected}, got {actual}")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        pg = browser.new_page(viewport={"width": 1100, "height": 1400}, accept_downloads=True)
        pg.goto(URL)
        pg.wait_for_selector("text=Quantum-safe certificates", timeout=60000)
        idle(pg, 1500)
        pg.get_by_role("button", name="Start over with a fresh university and archive").click()
        idle(pg, 1500)

        # 1. Issue
        pg.get_by_role("button", name="Issue certificate").click()
        idle(pg)
        shot(pg, "01_issue", "Certificate issued (2026-06-01), signed with ECDSA + ML-DSA", expected="-")
        with pg.expect_download() as dl:
            pg.get_by_role("button", name="Download certificate file").click()
        cert_file = os.path.join(OUT, dl.value.suggested_filename)  # keep the .json name
        dl.value.save_as(cert_file)

        # 2. Verify today
        tab(pg, "Verify")
        pg.get_by_text("Choose an issued certificate").click()
        idle(pg)
        shot(pg, "02_verify_genuine_today", "Genuine certificate verified today", "Verify a certificate", expected="Genuine")

        # 3-4. Tamper and restore
        pg.get_by_text("Upload a certificate file").click()
        idle(pg)
        pg.locator('[data-testid="stFileUploaderDropzoneInput"]').set_input_files(cert_file)
        idle(pg, 1200)
        area = pg.locator("textarea")
        data = json.loads(area.input_value())
        data["content"]["cgpa"] = "9.90"
        area.fill(json.dumps(data, indent=2))
        pg.get_by_text("Verify a certificate", exact=True).click()  # blur to commit the edit
        idle(pg, 1000)
        shot(pg, "03_tampered_rejected", "Uploaded certificate with CGPA edited 8.70 -> 9.90", "Verify a certificate",
             1500, expected="Rejected")
        pg.get_by_role("button", name="Restore original file").click()
        idle(pg, 1000)
        shot(pg, "04_restored_genuine", "Original file restored", "Verify a certificate", 1500, expected="Genuine")
        pg.get_by_text("Choose an issued certificate").click()
        idle(pg)

        # 5-6. Break ECDSA and ML-DSA, check in 2053
        tab(pg, "Simulate the future")
        tick(pg, "ECDSA-P256 broken")
        tick(pg, "ML-DSA-65 broken")
        shot(pg, "05_algorithms_broken", "ECDSA broken from 2045-03-01, ML-DSA from 2052-01-01", "Algorithm breaks",
             520, expected="-")
        tab(pg, "Verify")
        set_date(pg, "Check as of", "2053/01/01")
        shot(pg, "06_verify_2053_before_renewal", "Checked as of 2053, archive not renewed", "Verify a certificate", expected="Rejected")

        # 7-8. Renew in 2040 with SLH-DSA by all three authorities
        tab(pg, "Simulate the future")
        pg.get_by_role("button", name="Renew archive").click()
        idle(pg, 2500)
        shot(pg, "07_archive_renewed", "Archive renewed 2040-01-15: SLH-DSA, SHA3-512, 3 authorities",
             "Renew the archive", 640, expected="-")
        tab(pg, "Verify")
        shot(pg, "08_verify_2053_after_renewal", "Checked as of 2053 after renewal", "Verify a certificate", expected="Genuine")

        # 9-12. Forgeries
        tab(pg, "Simulate the future")
        forge = pg.get_by_role("button", name="Forge certificate")
        forge.click()
        idle(pg)
        shot(pg, "09_forgery_no_evidence", "Forged degree, stolen ECDSA key, no evidence", "Try a forgery", 1300, expected="Rejected")
        multiselect(pg, "Timestamp authorities the attacker controls", ["National Timestamp Service"])
        forge.click()
        idle(pg)
        shot(pg, "10_forgery_one_authority_2of3", "Forgery backdated by 1 compromised authority, 2 of 3 required",
             "Try a forgery", 1300, expected="Rejected")
        pg.get_by_text("1 of 3", exact=True).click()
        idle(pg)
        forge.click()
        idle(pg)
        shot(pg, "11_forgery_one_authority_1of3", "Same forgery with only 1 of 3 required (old weakness)",
             "Try a forgery", 1300, expected="Genuine")
        pg.get_by_text("2 of 3", exact=True).click()
        idle(pg)
        multiselect(pg, "Timestamp authorities the attacker controls",
                    ["National Timestamp Service", "Academic Consortium TSA"])
        forge.click()
        idle(pg)
        shot(pg, "12_forgery_two_colluding", "Forgery backdated by 2 colluding authorities (design limit)",
             "Try a forgery", 1300, expected="Genuine")

        # 13-14. BB84
        tab(pg, "Key transfer")
        pg.get_by_role("button", name="Run key exchange").click()
        idle(pg)
        shot(pg, "13_bb84_no_eavesdropper", "BB84 with no eavesdropper", "Move signing keys between offices", 700, expected="-")
        slider = pg.get_by_role("slider")
        slider.focus()
        slider.press("End")
        idle(pg)
        pg.get_by_role("button", name="Run key exchange").click()
        idle(pg)
        shot(pg, "14_bb84_eavesdropper", "BB84 with eavesdropper intercepting 100%",
             "Move signing keys between offices", 700, expected="-")
        browser.close()

    with open(f"{OUT}/results.md", "w", encoding="utf-8") as f:
        f.write("| # | Scenario | Expected | Actual | Result | Screenshot |\n"
                "| --- | --- | --- | --- | --- | --- |\n")
        for i, (name, caption, expected, actual) in enumerate(log, 1):
            result = "Done (no verdict)" if expected == "-" else ("Pass" if expected == actual else "FAIL")
            f.write(f"| {i} | {caption} | {expected} | {actual} | {result} | `{name}.png` |\n")
    print(f"\nSaved {len(log)} screenshots and results.md to ./{OUT}/")


if __name__ == "__main__":
    sys.exit(main())
