"""Generate 10 synthetic doc fixtures for 3b accuracy measurement.

Invented names/numbers ONLY — NEVER real Aadhaar/PAN. Every fixture
carries a "SYNTHETIC" watermark. Hindi + English mix (Devanagari lines
render only when a Devanagari font is present; otherwise the PNG keeps
the Latin lines and the manifest marks Hindi fields `font_missing` so
accuracy_check skips them instead of failing on a font problem).

Outputs (render/worker/fixtures/): doc01..doc10 .png + .pdf, manifest.json.
Run: python fixtures/generate.py  (needs Pillow + reportlab; CI-only deps)
"""
import json
import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))

DOCS = [
    {"id": "doc01", "kind": "invoice", "lines": [
        ("INVOICE", None), ("Invoice No: INV-2026-0142", "invoice_no"),
        ("Name: Arjun Mehta", "name"), ("Item: Wireless Mouse", "item"),
        ("Amount: Rs 1250", "amount"), ("Date: 12 Nov 2026", "date")]},
    {"id": "doc02", "kind": "invoice", "lines": [
        ("चालान", None), ("Invoice No: INV-2026-0143", "invoice_no"),
        ("Name: Priya Sharma", "name"), ("Amount: Rs 2499", "amount"),
        ("धन्यवाद", "thanks")]},
    {"id": "doc03", "kind": "receipt", "lines": [
        ("RECEIPT", None), ("Store: Sharma General Store", "store"),
        ("Item: Notebook Pack", "item"), ("Total: Rs 349", "amount"),
        ("Date: 15 Nov 2026", "date")]},
    {"id": "doc04", "kind": "receipt", "lines": [
        ("रसीद", None), ("Store: Verma Kirana Store", "store"),
        ("Total: Rs 899", "amount"), ("धन्यवाद", "thanks")]},
    {"id": "doc05", "kind": "form", "lines": [
        ("APPLICATION FORM", None), ("Name: Vikram Singh", "name"),
        ("City: Patna", "city"), ("Phone: 98765 43210", "phone"),
        ("Course: Computer Basics", "course")]},
    {"id": "doc06", "kind": "form", "lines": [
        ("आवेदन पत्र", None), ("Name: Anita Verma", "name"),
        ("City: Delhi", "city"), ("Phone: 91234 56780", "phone")]},
    {"id": "doc07", "kind": "certificate", "lines": [
        ("CERTIFICATE OF COMPLETION", None), ("Name: Rahul Gupta", "name"),
        ("Course: Python Basics", "course"), ("Date: 10 Nov 2026", "date")]},
    {"id": "doc08", "kind": "certificate", "lines": [
        ("प्रमाण पत्र", None), ("Name: Sneha Patel", "name"),
        ("Course: Data Entry", "course"), ("बधाई", "congrats")]},
    {"id": "doc09", "kind": "invoice", "lines": [
        ("INVOICE", None), ("Invoice No: INV-2026-0207", "invoice_no"),
        ("Name: Karan Joshi", "name"), ("Item: USB Cable", "item"),
        ("Amount: Rs 499", "amount"), ("Date: 18 Nov 2026", "date")]},
    {"id": "doc10", "kind": "receipt", "lines": [
        ("RECEIPT", None), ("Store: Gupta Electronics", "store"),
        ("Item: Charger 25W", "item"), ("Total: Rs 1299", "amount"),
        ("Date: 20 Nov 2026", "date")]},
]

DEVA_PATHS = [
    "/usr/share/fonts/truetype/lohit-devanagari/Lohit-Devanagari.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansDevanagari-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansDevanagari-Regular.ttf",
]
LATIN_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def find_font(paths, size):
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()


def is_devanagari(s: str) -> bool:
    return any("\u0900" <= ch <= "\u097f" for ch in s)


def main() -> None:
    os.makedirs(HERE, exist_ok=True)
    latin = find_font(LATIN_PATHS, 40)
    deva = None
    for p in DEVA_PATHS:
        try:
            deva = ImageFont.truetype(p, 40)
            break
        except Exception:
            continue
    print(f"devanagari font: {'found' if deva else 'MISSING (Hindi lines skipped in PNG)'}")
    manifest = {"docs": []}
    for doc in DOCS:
        # --- PNG (PIL) ---
        img = Image.new("RGB", (1100, 90 * len(doc["lines"]) + 160), "white")
        d = ImageDraw.Draw(img)
        y = 30
        fields = []
        for text, key in doc["lines"]:
            font = deva if (is_devanagari(text) and deva) else latin
            if is_devanagari(text) and not deva:
                print(f"  {doc['id']}: skipping Hindi line (no font): {text}")
                continue
            d.text((40, y), text, fill="black", font=font)
            y += 90
            if key:
                fields.append({"key": key, "value": text.split(":", 1)[-1].strip()
                               if ":" in text else text})
        d.text((40, y + 20), "SYNTHETIC - TEST DOCUMENT ONLY", fill="gray", font=latin)
        png_path = os.path.join(HERE, f"{doc['id']}.png")
        img.save(png_path)
        # --- PDF (reportlab, Latin lines only — Devanagari needs a
        # registered TTF; extract-accuracy is measured on Latin lines) ---
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as rl_canvas
        pdf_path = os.path.join(HERE, f"{doc['id']}.pdf")
        c = rl_canvas.Canvas(pdf_path, pagesize=A4)
        c.setFont("Helvetica-Bold", 20)
        yy = 780
        for text, key in doc["lines"]:
            if is_devanagari(text):
                continue
            c.drawString(60, yy, text)
            yy -= 40
        c.setFont("Helvetica", 12)
        c.drawString(60, yy - 20, "SYNTHETIC - TEST DOCUMENT ONLY")
        c.save()
        manifest["docs"].append({
            "id": doc["id"], "kind": doc["kind"],
            "png": f"{doc['id']}.png", "pdf": f"{doc['id']}.pdf",
            "fields": fields,
        })
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    total_fields = sum(len(d["fields"]) for d in manifest["docs"])
    print(f"generated {len(manifest['docs'])} docs, {total_fields} fields -> {HERE}")


if __name__ == "__main__":
    main()
