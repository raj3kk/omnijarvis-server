"""3b accuracy measurement: 10 synthetic docs, field-level accuracy.

Reads fixtures/manifest.json, OCRs each PNG via main._ocr_image_bytes
(real Tesseract) and extracts each PDF via main.extract (pdfplumber),
then checks every expected field value appears in the recognised text
(normalised: lowercase, non-alphanumerics stripped).

Exit gate (Pehle-Jaanch 3b §2c): aggregate field accuracy >= 0.85 AND
every per-doc accuracy >= 0.85. The gate is OCR-only (image path);
PDF-extract accuracy is reported separately, never a rescue for OCR.
Usage: python accuracy_check.py  (run from render/worker/)
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main as worker_main  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
THRESHOLD = 0.85


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def main() -> int:
    with open(os.path.join(FIX, "manifest.json")) as f:
        manifest = json.load(f)
    rows = []
    total = matched = 0
    for doc in manifest["docs"]:
        png_path = os.path.join(FIX, doc["png"])
        with open(png_path, "rb") as f:
            text, conf = worker_main._ocr_image_bytes(f.read())
        pdf_path = os.path.join(FIX, doc["pdf"])
        with open(pdf_path, "rb") as f:
            pdf_text = worker_main.extract(f.read())["text_preview"]
        ntext, npdf = norm(text), norm(pdf_text)
        doc_total = doc_matched = 0
        pdf_matched = 0
        misses = []
        for field in doc["fields"]:
            want = norm(field["value"])
            # PRIMARY gate: OCR-only (image path). PDF extract is a
            # separate cross-check number, never a rescue for OCR misses.
            hit = want in ntext
            pdf_hit = want in npdf
            doc_total += 1
            total += 1
            if hit:
                doc_matched += 1
                matched += 1
            else:
                misses.append(field["key"] + "=" + field["value"])
            if pdf_hit:
                pdf_matched += 1
        acc = doc_matched / doc_total if doc_total else 0.0
        pdf_acc = pdf_matched / doc_total if doc_total else 0.0
        rows.append((doc["id"], doc["kind"], doc_matched, doc_total, acc, conf, misses))
        print(f"{doc['id']} [{doc['kind']:11s}] OCR {doc_matched}/{doc_total} "
              f"acc={acc:.2f} extract_acc={pdf_acc:.2f} ocr_conf={conf:.1f}"
              + (f" MISS: {', '.join(misses)}" if misses else ""))
    agg = matched / total if total else 0.0
    print(f"AGGREGATE: {matched}/{total} acc={agg:.3f} (gate >= {THRESHOLD})")
    per_doc_ok = all(r[4] >= THRESHOLD for r in rows)
    print(f"PER-DOC GATE: {'PASS' if per_doc_ok else 'FAIL'} "
          f"(min per-doc acc={min(r[4] for r in rows):.2f})")
    if agg < THRESHOLD or not per_doc_ok:
        print("ACCURACY GATE FAILED")
        return 1
    print("ACCURACY GATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
