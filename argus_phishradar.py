#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARGUS PhishRadar — Visual Phishing Detection Engine
By Neurone4444

Scatta uno screenshot "live" di una URL (desktop o mobile) e lo passa a YOLO.
Fix principali:
- viewport configurabile (default DESKTOP 1366x768)
- screenshot full-page opzionale
- wait configurabile
- headless on/off
- user-agent configurabile (utile contro interstitial/anti-bot)
- imgsz YOLO configurabile (default 640)

Dipendenze:
  pip install ultralytics playwright
  python -m playwright install chromium

Esempio:
  python argus_phishradar.py --url "https://example.com" --yolo-model "best.pt" --fullpage --wait 3 --open
"""

import argparse
import os
import sys
import time
import webbrowser
import tempfile
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL = BASE_DIR / "models" / "best.pt"
DEFAULT_OUTPUT = BASE_DIR / "output"

# Optional: per annotare lo screenshot con box/circle/label
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# Optional: metriche visive (palette, hash, confronti)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except Exception:
    NUMPY_AVAILABLE = False

# Optional: CLIP brand recognition (zero-shot). Richiede download pesi la prima volta.
try:
    import torch
    from transformers import CLIPProcessor, CLIPModel
    CLIP_AVAILABLE = True
except Exception:
    CLIP_AVAILABLE = False

_CLIP_MODEL = None
_CLIP_PROCESSOR = None
_CLIP_MODEL_ID = "openai/clip-vit-base-patch32"

def banner():
    b = r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""
    print(b)
    print("ARGUS PhishRadar — Visual Phishing Detection Engine")
    print("By Neurone4444\n")

def now_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def is_probably_interstitial(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    needles = [
        "suspected phishing",
        "cloudflare ray id",
        "performance & security by cloudflare",
        "attention required",
        "ddos protection by cloudflare",
        "verify you are human",
        "checking your browser",
    ]
    return any(n in t for n in needles)

def take_screenshot_playwright(url: str, out_png: Path, *, headless: bool, width: int, height: int,
                               wait: float, fullpage: bool, user_agent: str | None,
                               bypass_csp: bool = True) -> dict:
    """
    Ritorna meta: {title, final_url, status_hint, interstitial_hint, html_title, screenshot_path}
    Nota: senza API esterne; si basa su what we can read dal DOM.
    """
    meta = {
        "title": None,
        "final_url": url,
        "status_hint": None,
        "interstitial_hint": False,
        "screenshot_path": str(out_png),
        "dom_signals": {},
        "load_state": None,
    }
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError("Playwright non disponibile. Installa: pip install playwright && python -m playwright install chromium") from e

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--disable-dev-shm-usage"])
        context_kwargs = {
            "viewport": {"width": width, "height": height},
            "bypass_csp": bypass_csp,
        }
        if user_agent:
            context_kwargs["user_agent"] = user_agent

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        # best-effort: riduce chance di "blank" su siti con lazy-load
        page.set_default_timeout(45000)

        resp = None
        try:
            resp = page.goto(url, wait_until="domcontentloaded")
            # prova a far finire il caricamento di rete; fallback su sleep
            try:
                page.wait_for_load_state("networkidle", timeout=max(1500, int(wait * 1000)))
                meta["load_state"] = "networkidle"
            except Exception:
                meta["load_state"] = "domcontentloaded"
                if wait and wait > 0:
                    time.sleep(wait)

            # prova a ottenere title e url finale
            try:
                meta["final_url"] = page.url
            except Exception:
                pass
            try:
                meta["title"] = page.title()
            except Exception:
                meta["title"] = None

            # heuristic interstitial
            body_text = ""
            try:
                body_text = page.inner_text("body")[:5000]
            except Exception:
                body_text = ""
            meta["interstitial_hint"] = is_probably_interstitial(body_text) or is_probably_interstitial(meta["title"] or "")

            # se sembra interstitial, aspetta un filo di più (spesso appare dopo 1-2s)
            if meta["interstitial_hint"] and wait < 2.5:
                time.sleep(2.5)

            # estrazione segnali DOM utili al mapping visuale
            try:
                dom_signals = {
                    "password_inputs": [],
                    "text_inputs": [],
                    "email_inputs": [],
                    "buttons": [],
                }
                def _bbox_for_all(selector: str):
                    out = []
                    try:
                        els = page.query_selector_all(selector)
                    except Exception:
                        els = []
                    for el in els[:10]:
                        try:
                            bb = el.bounding_box()
                            if bb:
                                out.append({
                                    "x": round(float(bb.get("x", 0.0)), 2),
                                    "y": round(float(bb.get("y", 0.0)), 2),
                                    "w": round(float(bb.get("width", 0.0)), 2),
                                    "h": round(float(bb.get("height", 0.0)), 2),
                                })
                        except Exception:
                            pass
                    return out

                dom_signals["password_inputs"] = _bbox_for_all('input[type="password"]')
                dom_signals["text_inputs"] = _bbox_for_all('input[type="text"]')
                dom_signals["email_inputs"] = _bbox_for_all('input[type="email"]')
                dom_signals["buttons"] = _bbox_for_all('button, input[type="submit"], input[type="button"]')
                try:
                    dom_signals["forms"] = page.locator("form").count()
                except Exception:
                    dom_signals["forms"] = 0
                meta["dom_signals"] = dom_signals
            except Exception:
                meta["dom_signals"] = {}

            # screenshot
            out_png.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(out_png), full_page=fullpage)
            meta["status_hint"] = getattr(resp, "status", None) if resp is not None else None

        finally:
            context.close()
            browser.close()

    return meta


def capture_live_session(url: str, out_png: Path, *, headless: bool, width: int, height: int,
                         wait: float, fullpage: bool, user_agent: str | None,
                         bypass_csp: bool = True,
                         step2_email: str | None = None,
                         step2_click_selectors: str | None = None) -> tuple[dict, dict, dict]:
    """
    Sessione Playwright unica: screenshot + meta + DOM intelligence + step2.
    Ritorna (meta, dom_intel, step2_info)
    """
    meta = {
        "title": None,
        "final_url": url,
        "status_hint": None,
        "interstitial_hint": False,
        "screenshot_path": str(out_png),
        "dom_signals": {},
        "load_state": None,
    }
    dom_intel = {}
    step2_info = {}

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError("Playwright non disponibile. Installa: pip install playwright && python -m playwright install chromium") from e

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--disable-dev-shm-usage"])
        context_kwargs = {
            "viewport": {"width": width, "height": height},
            "bypass_csp": bypass_csp,
        }
        if user_agent:
            context_kwargs["user_agent"] = user_agent

        context = browser.new_context(**context_kwargs)
        page = context.new_page()
        page.set_default_timeout(45000)
        resp = None
        try:
            resp = page.goto(url, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=max(1500, int(wait * 1000)))
                meta["load_state"] = "networkidle"
            except Exception:
                meta["load_state"] = "domcontentloaded"
                if wait and wait > 0:
                    time.sleep(wait)

            if step2_email:
                step2_info = advance_to_step2(page, step2_email, step2_click_selectors or "")
                try:
                    if step2_info.get("clicked") or step2_info.get("email_filled"):
                        try:
                            page.wait_for_load_state("networkidle", timeout=7000)
                        except Exception:
                            pass
                except Exception:
                    pass

            try:
                meta["final_url"] = page.url
            except Exception:
                pass
            try:
                meta["title"] = page.title()
            except Exception:
                meta["title"] = None

            body_text = ""
            try:
                body_text = page.inner_text("body")[:5000]
            except Exception:
                body_text = ""
            meta["interstitial_hint"] = is_probably_interstitial(body_text) or is_probably_interstitial(meta["title"] or "")
            if meta["interstitial_hint"] and wait < 2.5:
                time.sleep(2.5)

            try:
                dom_signals = {
                    "password_inputs": [],
                    "text_inputs": [],
                    "email_inputs": [],
                    "buttons": [],
                }
                def _bbox_for_all(selector: str):
                    out = []
                    try:
                        els = page.query_selector_all(selector)
                    except Exception:
                        els = []
                    for el in els[:10]:
                        try:
                            bb = el.bounding_box()
                            if bb:
                                out.append({
                                    "x": round(float(bb.get("x", 0.0)), 2),
                                    "y": round(float(bb.get("y", 0.0)), 2),
                                    "w": round(float(bb.get("width", 0.0)), 2),
                                    "h": round(float(bb.get("height", 0.0)), 2),
                                })
                        except Exception:
                            pass
                    return out

                dom_signals["password_inputs"] = _bbox_for_all('input[type="password"]')
                dom_signals["text_inputs"] = _bbox_for_all('input[type="text"]')
                dom_signals["email_inputs"] = _bbox_for_all('input[type="email"]')
                dom_signals["buttons"] = _bbox_for_all('button, input[type="submit"], input[type="button"]')
                try:
                    dom_signals["forms"] = page.locator("form").count()
                except Exception:
                    dom_signals["forms"] = 0
                meta["dom_signals"] = dom_signals
            except Exception:
                meta["dom_signals"] = {}

            try:
                dom_intel = extract_dom_intelligence(page)
            except Exception:
                dom_intel = {}

            out_png.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(out_png), full_page=fullpage)
            meta["status_hint"] = getattr(resp, "status", None) if resp is not None else None
        finally:
            context.close()
            browser.close()

    return meta, dom_intel, step2_info


def annotate_screenshot(screenshot_png: Path, detections: list[dict], out_png: Path) -> bool:
    """
    Crea un PNG annotato sullo screenshot originale:
      - rettangolo (bbox)
      - cerchio centrato sul bbox (utile per evidenziare anche su UI dense)
      - label + conf
    Ritorna True se salvato, False se non possibile.
    """
    if not PIL_AVAILABLE:
        return False
    try:
        img = Image.open(screenshot_png).convert("RGBA")
        draw = ImageDraw.Draw(img)

        # font best-effort (evita dipendenze)
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None

        for d in detections:
            xyxy = d.get("xyxy") or []
            if len(xyxy) != 4:
                continue
            x1, y1, x2, y2 = map(float, xyxy)
            name = str(d.get("name", "obj"))
            conf = float(d.get("conf", 0.0))

            # bbox
            draw.rectangle([x1, y1, x2, y2], outline=(0, 255, 0, 255), width=3)

            # circle around bbox center
            cx = (x1 + x2) / 2.0
            cy = (y1 + y2) / 2.0
            w = max(1.0, (x2 - x1))
            h = max(1.0, (y2 - y1))
            r = max(w, h) / 2.0
            pad = max(6.0, r * 0.08)
            rr = r + pad
            draw.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=(255, 215, 0, 255), width=3)

            # label box
            label = f"{name} {conf:.2f}"
            tx = x1
            ty = max(0, y1 - 16)
            # background for readability
            draw.rectangle([tx, ty, tx + 8 + 7 * len(label), ty + 16], fill=(0, 0, 0, 160))
            draw.text((tx + 4, ty + 2), label, fill=(255, 255, 255, 255), font=font)

        out_png.parent.mkdir(parents=True, exist_ok=True)
        img = img.convert("RGB")
        img.save(out_png, format="PNG")
        return True
    except Exception:
        return False


def compute_palette(image_path: Path, k: int = 6) -> list[str]:
    """
    Estrae una palette (k colori) in HEX dallo screenshot.
    Usa quantizzazione PIL (senza sklearn).
    """
    if not PIL_AVAILABLE:
        return []
    try:
        img = Image.open(image_path).convert("RGB")
        # Riduci per velocità
        img_small = img.resize((max(64, img.width // 4), max(64, img.height // 4)))
        q = img_small.quantize(colors=max(2, min(16, k)), method=2)
        pal = q.getpalette()  # list
        # Conta colori usati
        colors = q.getcolors()
        if not colors:
            return []
        colors = sorted(colors, key=lambda x: x[0], reverse=True)[:k]
        hexes = []
        for _, idx in colors:
            r, g, b = pal[idx*3:idx*3+3]
            hexes.append(f"#{r:02x}{g:02x}{b:02x}")
        # Unici mantenendo ordine
        out = []
        for h in hexes:
            if h not in out:
                out.append(h)
        return out[:k]
    except Exception:
        return []

def compute_ahash(image_path: Path, hash_size: int = 8) -> str | None:
    """
    Average-hash (aHash) robusto e leggero. Ritorna stringa esadecimale.
    """
    if not (PIL_AVAILABLE and NUMPY_AVAILABLE):
        return None
    try:
        img = Image.open(image_path).convert("L").resize((hash_size, hash_size))
        arr = np.array(img, dtype=np.float32)
        mean = arr.mean()
        bits = (arr > mean).astype(np.uint8).flatten()
        # pack bits into hex string
        h = 0
        hex_out = []
        for i, b in enumerate(bits):
            h = (h << 1) | int(b)
            if (i + 1) % 4 == 0:
                hex_out.append(format(h, "x"))
                h = 0
        return "".join(hex_out)
    except Exception:
        return None

def hamming_hex(a: str | None, b: str | None) -> int | None:
    if not a or not b or len(a) != len(b):
        return None
    try:
        # Each hex nibble = 4 bits
        dist = 0
        for ca, cb in zip(a, b):
            va = int(ca, 16)
            vb = int(cb, 16)
            dist += bin(va ^ vb).count("1")
        return dist
    except Exception:
        return None

def compare_yolo_positions(dets_a: list[dict], dets_b: list[dict], *, w: int, h: int, tol: float = 0.06) -> dict:
    """
    Confronta posizioni (centro bbox) tra due screenshot per classi comuni.
    tol = soglia su distanza normalizzata per contare mismatch.
    Ritorna {common, mismatched, mismatch_rate, details[]}
    """
    # prendi detection migliore per classe (conf max)
    def best_by_class(dets):
        best = {}
        for d in dets:
            name = d.get("name")
            conf = float(d.get("conf", 0))
            if not name or "xyxy" not in d:
                continue
            if name not in best or conf > best[name]["conf"]:
                best[name] = {"conf": conf, "xyxy": d["xyxy"]}
        return best

    A = best_by_class(dets_a)
    B = best_by_class(dets_b)
    common = sorted(set(A.keys()) & set(B.keys()))
    details = []
    mism = 0
    for c in common:
        ax1, ay1, ax2, ay2 = map(float, A[c]["xyxy"])
        bx1, by1, bx2, by2 = map(float, B[c]["xyxy"])
        acx, acy = (ax1+ax2)/2, (ay1+ay2)/2
        bcx, bcy = (bx1+bx2)/2, (by1+by2)/2
        dx = (acx - bcx) / max(1.0, float(w))
        dy = (acy - bcy) / max(1.0, float(h))
        d = (dx*dx + dy*dy) ** 0.5
        is_mismatch = d > tol
        mism += 1 if is_mismatch else 0
        details.append({
            "class": c,
            "dist_norm": round(d, 4),
            "mismatch": bool(is_mismatch),
            "a_conf": round(float(A[c]["conf"]), 3),
            "b_conf": round(float(B[c]["conf"]), 3),
        })
    rate = (mism / len(common)) if common else 0.0
    return {
        "common": len(common),
        "mismatched": mism,
        "mismatch_rate": round(rate, 3),
        "tol": tol,
        "details": details,
    }


def clip_brand_recognition(image_path: Path, brands: list[str], *, device: str = "cpu") -> dict:
    """
    Zero-shot brand recognition via CLIP su uno o più crop dello screenshot.
    Ritorna:
      {
        "available": bool,
        "device": "cpu/cuda",
        "top_brand": str|None,
        "top_score": float|None,
        "scores": [{"brand":..,"score":..},...],
        "crops_used": int
      }
    Note:
      - richiede: pip install transformers torch
      - la prima volta scarica il modello (internet)
    """
    out = {"available": False, "device": device, "top_brand": None, "top_score": None, "scores": [], "crops_used": 0}
    if not (CLIP_AVAILABLE and PIL_AVAILABLE):
        return out
    if not brands:
        return out
    try:
        global _CLIP_MODEL, _CLIP_PROCESSOR
        if _CLIP_MODEL is None or _CLIP_PROCESSOR is None:
            _CLIP_MODEL = CLIPModel.from_pretrained(_CLIP_MODEL_ID)
            _CLIP_PROCESSOR = CLIPProcessor.from_pretrained(_CLIP_MODEL_ID)
        model = _CLIP_MODEL
        proc = _CLIP_PROCESSOR
        dev = device
        if dev == "cuda" and torch.cuda.is_available():
            model = model.to("cuda")
            dev = "cuda"
        else:
            model = model.to("cpu")
            dev = "cpu"
        out["device"] = dev

        img = Image.open(image_path).convert("RGB")
        W, H = img.size

        # Crop euristiche dove spesso sta il logo (top-left / top-center) + centro card
        crops = []
        # top-left
        crops.append(img.crop((0, 0, int(W * 0.45), int(H * 0.35))))
        # top-center
        crops.append(img.crop((int(W * 0.2), 0, int(W * 0.8), int(H * 0.35))))
        # center (per card login)
        crops.append(img.crop((int(W * 0.2), int(H * 0.15), int(W * 0.8), int(H * 0.75))))

        texts = [f"logo of {b}" for b in brands] + [f"{b} login page" for b in brands]
        # Per evitare duplicati enormi
        # Calcolo score massimo per brand su tutti i prompt e crop
        brand_scores = {b: -1e9 for b in brands}

        model.eval()
        with torch.no_grad():
            for cimg in crops:
                inputs = proc(text=texts, images=cimg, return_tensors="pt", padding=True)
                if dev == "cuda":
                    inputs = {k: v.to("cuda") for k, v in inputs.items()}
                outputs = model(**inputs)
                logits = outputs.logits_per_image[0]  # shape [num_texts]
                probs = logits.softmax(dim=0).detach().cpu().numpy().tolist()

                # Map prompts back to brands (2 prompts per brand)
                for i, b in enumerate(brands):
                    p1 = probs[i]  # "logo of b"
                    p2 = probs[i + len(brands)]  # "b login page"
                    brand_scores[b] = max(brand_scores[b], float(max(p1, p2)))

        scores = [{"brand": b, "score": round(float(brand_scores[b]), 4)} for b in brands]
        scores.sort(key=lambda x: x["score"], reverse=True)

        out["available"] = True
        out["scores"] = scores
        out["crops_used"] = len(crops)
        if scores:
            out["top_brand"] = scores[0]["brand"]
            out["top_score"] = scores[0]["score"]
        return out
    except Exception:
        return out



def build_layout_fingerprint(detections: list[dict], *, width: int, height: int) -> dict:
    """
    Costruisce una fingerprint del layout usando le detection YOLO.
    """
    if not detections or width <= 0 or height <= 0:
        return {"elements": [], "relations": [], "signature": None, "summary": ""}

    best = {}
    for d in detections:
        name = d.get("name")
        xyxy = d.get("xyxy")
        conf = float(d.get("conf", 0.0))
        if not name or not xyxy or len(xyxy) != 4:
            continue
        if name not in best or conf > best[name]["conf"]:
            best[name] = {"conf": conf, "xyxy": xyxy}

    elements = []
    for name, item in best.items():
        x1, y1, x2, y2 = map(float, item["xyxy"])
        cx = ((x1 + x2) / 2.0) / float(width)
        cy = ((y1 + y2) / 2.0) / float(height)
        w = max(0.0, (x2 - x1)) / float(width)
        h = max(0.0, (y2 - y1)) / float(height)
        area = w * h
        elements.append({
            "class": name,
            "conf": round(float(item["conf"]), 3),
            "cx": round(cx, 4),
            "cy": round(cy, 4),
            "w": round(w, 4),
            "h": round(h, 4),
            "area": round(area, 4),
        })

    elements.sort(key=lambda x: x["class"])

    relations = []
    for i in range(len(elements)):
        for j in range(i + 1, len(elements)):
            a = elements[i]
            b = elements[j]
            dx = b["cx"] - a["cx"]
            dy = b["cy"] - a["cy"]
            dist = (dx * dx + dy * dy) ** 0.5
            relations.append({
                "pair": f'{a["class"]}->{b["class"]}',
                "dx": round(dx, 4),
                "dy": round(dy, 4),
                "dist": round(dist, 4),
            })

    relations.sort(key=lambda x: x["pair"])

    summary_parts = [
        f'{e["class"]}@{e["cx"]:.3f},{e["cy"]:.3f}:{e["w"]:.3f}x{e["h"]:.3f}'
        for e in elements
    ]
    relation_parts = [
        f'{r["pair"]}:{r["dx"]:.3f},{r["dy"]:.3f},{r["dist"]:.3f}'
        for r in relations
    ]
    summary = "|".join(summary_parts + relation_parts)
    signature = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:24]

    return {
        "elements": elements,
        "relations": relations,
        "summary": summary,
        "signature": signature,
        "n_elements": len(elements),
        "n_relations": len(relations),
    }

def compare_layout_fingerprints(fp_a: dict | None, fp_b: dict | None) -> dict:
    out = {
        "common_classes": 0,
        "position_shift_avg": None,
        "size_shift_avg": None,
        "same_signature": False,
    }
    if not fp_a or not fp_b:
        return out
    a_elems = {e["class"]: e for e in (fp_a.get("elements") or [])}
    b_elems = {e["class"]: e for e in (fp_b.get("elements") or [])}
    common = sorted(set(a_elems) & set(b_elems))
    out["common_classes"] = len(common)
    if common:
        pos_shifts = []
        size_shifts = []
        for c in common:
            a = a_elems[c]
            b = b_elems[c]
            pos = ((a["cx"] - b["cx"]) ** 2 + (a["cy"] - b["cy"]) ** 2) ** 0.5
            size = (abs(a["w"] - b["w"]) + abs(a["h"] - b["h"])) / 2.0
            pos_shifts.append(pos)
            size_shifts.append(size)
        out["position_shift_avg"] = round(sum(pos_shifts) / len(pos_shifts), 4)
        out["size_shift_avg"] = round(sum(size_shifts) / len(size_shifts), 4)
    out["same_signature"] = bool(fp_a.get("signature") and fp_a.get("signature") == fp_b.get("signature"))
    return out


def extract_dom_intelligence(page):
    """
    Estrae informazioni utili dal DOM per analisi phishing:
    - link presenti
    - form action
    - input types
    - possibili endpoint di esfiltrazione
    """
    intel = {
        "links": [],
        "form_actions": [],
        "input_types": [],
        "scripts": [],
    }

    try:
        # links
        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        intel["links"] = list(set(links))[:100]
    except:
        pass

    try:
        forms = page.eval_on_selector_all("form", "els => els.map(e => e.action)")
        intel["form_actions"] = list(set(forms))
    except:
        pass

    try:
        inputs = page.eval_on_selector_all("input", "els => els.map(e => e.type)")
        intel["input_types"] = list(set(inputs))
    except:
        pass

    try:
        scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
        intel["scripts"] = list(set(scripts))[:50]
    except:
        pass

    return intel



def filter_anomalous_detections(detections: list[dict], *, width: int, height: int) -> tuple[list[dict], list[dict]]:
    """
    Filtra detection palesemente anomale per alcune classi UI.
    Utile per evitare falsi positivi come header/topbar classificati come login_button.
    """
    kept = []
    removed = []
    for d in detections:
        xyxy = d.get("xyxy") or []
        name = str(d.get("name", ""))
        if len(xyxy) != 4 or width <= 0 or height <= 0:
            kept.append(d)
            continue
        x1, y1, x2, y2 = map(float, xyxy)
        bw = max(0.0, x2 - x1)
        bh = max(0.0, y2 - y1)
        area_ratio = (bw * bh) / float(width * height)
        width_ratio = bw / float(width)
        height_ratio = bh / float(height)
        top_ratio = y1 / float(height)

        suspicious = False
        # Header/banner scambiati per login_button/link
        if name in {"login_button", "forgot_password_link", "remember_me_checkbox"}:
            if area_ratio > 0.12 or width_ratio > 0.65 or (top_ratio < 0.12 and width_ratio > 0.45):
                suspicious = True
        # Campi input improbabili enormi
        if name in {"username_field", "password_field", "2fa_field"}:
            if area_ratio > 0.20 or height_ratio > 0.18 or width_ratio > 0.85:
                suspicious = True

        if suspicious:
            removed.append({
                **d,
                "filtered_reason": {
                    "area_ratio": round(area_ratio, 4),
                    "width_ratio": round(width_ratio, 4),
                    "height_ratio": round(height_ratio, 4),
                    "top_ratio": round(top_ratio, 4),
                }
            })
        else:
            kept.append(d)
    return kept, removed


def advance_to_step2(page, email_value: str, selectors_csv: str) -> dict:
    """
    Best-effort: inserisce una email e prova ad avanzare al secondo step.
    Utile per Microsoft/Google login a step multipli.
    """
    out = {"attempted": False, "email_filled": False, "clicked": False, "final_url": None, "title": None}
    try:
        email_selectors = [
            "input[type=email]",
            "input[name=loginfmt]",
            "input[name=email]",
            "input[type=text]",
        ]
        field = None
        for sel in email_selectors:
            try:
                field = page.locator(sel).first
                if field.count() > 0:
                    break
            except Exception:
                field = None
        if field is not None:
            out["attempted"] = True
            try:
                field.fill(email_value)
                out["email_filled"] = True
            except Exception:
                try:
                    field.click()
                    field.type(email_value, delay=20)
                    out["email_filled"] = True
                except Exception:
                    pass

        selectors = [s.strip() for s in (selectors_csv or "").split(",") if s.strip()]
        for sel in selectors:
            if out["clicked"]:
                break
            try:
                if sel.startswith("text="):
                    page.get_by_text(sel.split("=", 1)[1], exact=False).first.click(timeout=2500)
                else:
                    page.locator(sel).first.click(timeout=2500)
                out["clicked"] = True
            except Exception:
                continue

        try:
            page.wait_for_load_state("networkidle", timeout=7000)
        except Exception:
            pass
        out["final_url"] = page.url
        try:
            out["title"] = page.title()
        except Exception:
            pass
    except Exception:
        pass
    return out

def run_yolo(model_path: str, image_path: str, *, imgsz: int, conf: float, iou: float):
    try:
        from ultralytics import YOLO
    except Exception as e:
        raise RuntimeError("Ultralytics non disponibile. Installa: pip install ultralytics") from e

    m = YOLO(model_path)
    # verbose=False per ridurre rumore, ma Ultralytics comunque stampa una riga: ok
    results = m.predict(source=image_path, imgsz=imgsz, conf=conf, iou=iou, verbose=False)
    return results



def extract_hostname(value: str | None) -> str:
    if not value:
        return ""
    try:
        host = (urlparse(value).hostname or "").lower()
        return host
    except Exception:
        return ""

def domain_matches_brand(brand: str | None, url_or_domain: str | None, custom_allowlist: str | None = None) -> bool:
    brand = (brand or "").strip().lower()
    host = extract_hostname(url_or_domain) if "://" in str(url_or_domain or "") else (str(url_or_domain or "").lower())
    if not brand or not host:
        return False

    builtin = {
        "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com", "office365.com"],
        "google": ["google.com", "googleusercontent.com", "gstatic.com", "withgoogle.com", "youtube.com", "gmail.com"],
        "apple": ["apple.com", "icloud.com", "me.com"],
        "paypal": ["paypal.com"],
        "amazon": ["amazon.com", "amazon.it", "amazonaws.com"],
        "facebook": ["facebook.com", "fb.com", "meta.com", "messenger.com"],
        "instagram": ["instagram.com", "cdninstagram.com"],
        "linkedin": ["linkedin.com", "licdn.com"],
        "netflix": ["netflix.com"],
        "x": ["x.com", "twitter.com", "t.co"],
        "twitter": ["twitter.com", "x.com", "t.co"],
    }
    allowed = list(builtin.get(brand, []))
    if custom_allowlist:
        for item in str(custom_allowlist).split(","):
            item = item.strip().lower()
            if item:
                allowed.append(item)
    for dom in allowed:
        if host == dom or host.endswith("." + dom):
            return True
    if brand in host:
        return True
    return False

def filter_suspicious_large_boxes(detections: list[dict], width: int, height: int) -> tuple[list[dict], list[dict]]:
    """
    Rimuove alcuni falsi positivi grossolani: box enormi per classi che di solito sono piccole/medie.
    """
    if width <= 0 or height <= 0:
        return detections, []
    kept, removed = [], []
    for d in detections:
        xyxy = d.get("xyxy") or []
        name = d.get("name") or ""
        if len(xyxy) != 4:
            kept.append(d)
            continue
        x1, y1, x2, y2 = map(float, xyxy)
        bw = max(0.0, x2 - x1)
        bh = max(0.0, y2 - y1)
        area_ratio = (bw * bh) / float(max(1, width * height))
        h_ratio = bh / float(max(1, height))
        suspicious = name in {"login_button", "forgot_password_link", "remember_me_checkbox"} and (area_ratio > 0.25 or h_ratio > 0.18)
        if suspicious:
            removed.append({**d, "filtered_reason": "oversized_bbox"})
        else:
            kept.append(d)
    return kept, removed

def best_detection_by_class(detections: list[dict], class_name: str) -> dict | None:
    cands = [d for d in detections if d.get("name") == class_name and (d.get("xyxy") and len(d.get("xyxy")) == 4)]
    if not cands:
        return None
    cands.sort(key=lambda x: float(x.get("conf", 0.0)), reverse=True)
    return cands[0]

def _bbox_center_norm_from_xyxy(xyxy: list[float], width: int, height: int) -> tuple[float, float]:
    x1, y1, x2, y2 = map(float, xyxy)
    return (((x1 + x2) / 2.0) / float(max(1, width)), ((y1 + y2) / 2.0) / float(max(1, height)))

def dom_visual_mapping(meta: dict, detections: list[dict], width: int, height: int, tol: float = 0.12) -> dict:
    """
    Confronta alcune detection YOLO con gli elementi reali del DOM.
    """
    dom = (meta or {}).get("dom_signals") or {}
    result = {
        "available": bool(dom),
        "pairs": [],
        "missing_in_dom": [],
        "score": None,
    }
    if not dom:
        return result

    selector_map = {
        "username_field": (dom.get("email_inputs") or []) + (dom.get("text_inputs") or []),
        "password_field": dom.get("password_inputs") or [],
        "login_button": dom.get("buttons") or [],
    }

    matched = 0
    total = 0
    for cls, dom_boxes in selector_map.items():
        det = best_detection_by_class(detections, cls)
        if not det:
            continue
        total += 1
        if not dom_boxes:
            result["missing_in_dom"].append(cls)
            result["pairs"].append({"class": cls, "matched": False, "reason": "dom_missing"})
            continue
        dcx, dcy = _bbox_center_norm_from_xyxy(det["xyxy"], width, height)
        best_dist = None
        for bb in dom_boxes:
            cx = (float(bb["x"]) + float(bb["w"]) / 2.0) / float(max(1, width))
            cy = (float(bb["y"]) + float(bb["h"]) / 2.0) / float(max(1, height))
            dist = ((dcx - cx) ** 2 + (dcy - cy) ** 2) ** 0.5
            if best_dist is None or dist < best_dist:
                best_dist = dist
        is_match = best_dist is not None and best_dist <= tol
        matched += 1 if is_match else 0
        result["pairs"].append({"class": cls, "matched": bool(is_match), "best_dist": round(float(best_dist or 0.0), 4), "tol": tol})
    if total > 0:
        result["score"] = round(matched / total, 3)
    return result

def get_avg_color_for_detection(image_path: Path, detection: dict | None) -> dict | None:
    if not PIL_AVAILABLE or not detection:
        return None
    try:
        xyxy = detection.get("xyxy") or []
        if len(xyxy) != 4:
            return None
        img = Image.open(image_path).convert("RGB")
        x1, y1, x2, y2 = [int(max(0, round(v))) for v in xyxy]
        x2 = min(img.width, max(x1 + 1, x2))
        y2 = min(img.height, max(y1 + 1, y2))
        crop = img.crop((x1, y1, x2, y2))
        small = crop.resize((1, 1))
        r, g, b = small.getpixel((0, 0))
        return {"rgb": [int(r), int(g), int(b)], "hex": f"#{int(r):02x}{int(g):02x}{int(b):02x}"}
    except Exception:
        return None

def color_distance_rgb(a: dict | None, b: dict | None) -> float | None:
    try:
        if not a or not b:
            return None
        ar, ag, ab = a["rgb"]
        br, bg, bb = b["rgb"]
        return round((((ar-br)**2 + (ag-bg)**2 + (ab-bb)**2) ** 0.5), 2)
    except Exception:
        return None



def detect_cookie_banner_context(dom_intel: dict | None = None, meta: dict | None = None) -> dict:
    dom_intel = dom_intel or {}
    meta = meta or {}
    scripts = [str(s).lower() for s in (dom_intel.get("scripts") or [])]
    links = [str(s).lower() for s in (dom_intel.get("links") or [])]
    forms = [str(s).lower() for s in (dom_intel.get("form_actions") or [])]
    title = str(meta.get("title") or "").lower()

    strong_needles = [
        "cookie", "consent", "gdpr", "cmp", "gatekeeper",
        "onetrust", "didomi", "iubenda", "quantcast", "trustarc",
        "cookiebot", "consentmanager", "cookieyes"
    ]
    weak_needles = [
        "privacy", "privacystatement"
    ]

    strong_hits = []
    weak_hits = []
    sources = scripts + links + forms + [title]
    for needle in strong_needles:
        if any(needle in s for s in sources):
            strong_hits.append(needle)
    for needle in weak_needles:
        if any(needle in s for s in sources):
            weak_hits.append(needle)

    is_cookie_context = bool(strong_hits)
    hits = sorted(set(strong_hits + (weak_hits if is_cookie_context else [])))

    return {
        "is_cookie_context": is_cookie_context,
        "hits": hits,
        "strong_hits": sorted(set(strong_hits)),
        "weak_hits": sorted(set(weak_hits)),
    }


def suppress_cookie_banner_false_positives(detections: list[dict], dom_intel: dict | None = None, meta: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    cookie_ctx = detect_cookie_banner_context(dom_intel=dom_intel, meta=meta)
    names = [str(d.get("name", "")) for d in detections]
    credential_like = {"username_field", "password_field", "login_button"}
    has_credential_combo = ("login_button" in names) and (("username_field" in names) or ("password_field" in names))
    has_password = "password_field" in names

    if not cookie_ctx.get("is_cookie_context"):
        return detections, [], cookie_ctx

    kept = []
    suppressed = []
    suppressible = {"2fa_field", "security_alert", "captcha", "forgot_password_link"}

    for d in detections:
        name = str(d.get("name", ""))
        if (name in suppressible) and (not has_password) and (not has_credential_combo):
            suppressed.append({**d, "filtered_reason": "cookie_banner_context"})
        else:
            kept.append(d)

    return kept, suppressed, cookie_ctx


def benign_site_adjustment(detections: list[dict], meta: dict, visual_metrics: dict, dom_intel: dict | None = None) -> tuple[int, list[str]]:
    dom_intel = dom_intel or {}
    reasons = []
    adjust = 0
    names = [str(d.get("name", "")) for d in detections]
    host = extract_hostname((meta or {}).get("final_url") or (meta or {}).get("url") or "")

    cookie_ctx = (visual_metrics or {}).get("cookie_banner_context") or detect_cookie_banner_context(dom_intel=dom_intel, meta=meta)
    if cookie_ctx.get("is_cookie_context"):
        adjust -= 12
        reasons.append("cookie/privacy banner context")

    hard_dom_gate = (visual_metrics or {}).get("hard_dom_gate") or {}
    if hard_dom_gate.get("active"):
        adjust -= 10
        reasons.append("DOM has no password field; login-like YOLO detections suppressed")

    scripts = [str(s).lower() for s in (dom_intel.get("scripts") or [])]
    suspicious_script_needles = ["emailjs", "smtpjs", "telegram", "discord", "webhook", "formsubmit", "getform", "sheetdb"]
    if scripts and not any(any(n in s for n in suspicious_script_needles) for s in scripts):
        adjust -= 4
        reasons.append("scripts look benign/common")

    form_actions = [str(f).lower() for f in (dom_intel.get("form_actions") or [])]
    if host and form_actions:
        if all((extract_hostname(f) == host) or f.startswith("javascript:") or f in {"", "#"} for f in form_actions):
            adjust -= 4
            reasons.append("form actions stay on same host")

    clip = (visual_metrics or {}).get("clip_brand") or {}
    top_score = float(clip.get("top_score") or 0.0)
    mismatch = (visual_metrics or {}).get("brand_domain_mismatch")
    if (mismatch is False) or (not mismatch and top_score < 0.85):
        adjust -= 3
        reasons.append("no strong brand-domain mismatch")

    high_risk_combo = ("password_field" in names) or (("login_button" in names) and (("username_field" in names) or ("password_field" in names)))
    if not high_risk_combo and any(n in names for n in ["2fa_field", "security_alert", "captcha"]):
        adjust -= 6
        reasons.append("isolated UI signals without credential flow")

    return adjust, reasons


def contextual_risk(detections: list[dict], meta: dict, visual_metrics: dict, dom_intel: dict | None = None, custom_allowlist: str | None = None) -> tuple[int, list[str]]:
    names = [d.get("name") for d in detections]
    final_url = (meta or {}).get("final_url") or (meta or {}).get("url") or ""
    clip = (visual_metrics or {}).get("clip_brand") or {}
    top_brand = clip.get("top_brand")
    top_score = float(clip.get("top_score") or 0.0)
    dom_intel = dom_intel or {}
    reasons = []
    bonus = 0

    mismatch = False
    if top_brand and top_score >= 0.85:
        mismatch = not domain_matches_brand(top_brand, final_url, custom_allowlist=custom_allowlist)
        visual_metrics["brand_domain_mismatch"] = mismatch
        if mismatch:
            if top_score >= 0.95:
                bonus += 50
                reasons.append(f"brand-domain mismatch ({top_brand}, CLIP {top_score:.2f})")
            else:
                bonus += 35
                reasons.append(f"strong brand-domain mismatch ({top_brand}, CLIP {top_score:.2f})")

    if ("password_field" in names) and ("login_button" in names) and mismatch:
        reasons.append("password field + login button + brand mismatch")
        return 100, reasons

    if (("username_field" in names) or ("password_field" in names)) and ("login_button" in names) and mismatch and top_score >= 0.90:
        bonus += 25
        reasons.append("credential UI + high-confidence brand mismatch")

    mapping = (visual_metrics or {}).get("dom_visual_mapping") or {}
    if mapping.get("available") and mapping.get("missing_in_dom"):
        miss = mapping.get("missing_in_dom") or []
        if "password_field" in miss:
            bonus += 20
            reasons.append("YOLO sees password field but DOM does not")
        elif miss:
            bonus += 10
            reasons.append("YOLO/DOM mismatch on key fields")

    if (visual_metrics or {}).get("button_color_compare"):
        cdist = (visual_metrics["button_color_compare"] or {}).get("distance")
        if cdist is not None and cdist >= 40:
            bonus += 8
            reasons.append(f"login button color drift ({cdist})")

    if (visual_metrics or {}).get("layout_compare"):
        same_sig = (visual_metrics["layout_compare"] or {}).get("same_signature")
        if same_sig:
            reasons.append("same layout signature as reference")
        elif (visual_metrics["layout_compare"] or {}).get("common_classes", 0) >= 2:
            bonus += 6
            reasons.append("layout partially aligned with reference")

    if (visual_metrics or {}).get("filtered_out"):
        removed_n = len((visual_metrics or {}).get("filtered_out") or [])
        if removed_n:
            reasons.append(f"filtered {removed_n} oversized detections")

    scripts = [str(s).lower() for s in (dom_intel.get("scripts") or [])]
    exfil_hits = []
    exfil_map = {
        "emailjs": 35,
        "smtpjs": 35,
        "telegram": 40,
        "discord": 35,
        "webhook": 35,
        "formsubmit": 30,
        "getform": 30,
        "sheetdb": 30,
    }
    exfil_bonus = 0
    for needle, pts in exfil_map.items():
        if any(needle in s for s in scripts):
            exfil_hits.append(needle)
            exfil_bonus = max(exfil_bonus, pts)
    if exfil_hits:
        bonus += exfil_bonus
        reasons.append(f"possible exfiltration script: {', '.join(sorted(set(exfil_hits)))}")

    host = extract_hostname(final_url)
    suspicious_hosts = ["github.io", "pages.dev", "netlify.app", "vercel.app"]
    if top_brand and any(host == h or host.endswith('.' + h) for h in suspicious_hosts):
        bonus += 25
        reasons.append("free-hosting brand impersonation")

    if str(final_url).lower().startswith("http://") and (("login_button" in names) or ("password_field" in names) or ("username_field" in names)):
        bonus += 20
        reasons.append("insecure HTTP credential page")

    cookie_ctx = (visual_metrics or {}).get("cookie_banner_context") or {}
    if cookie_ctx.get("is_cookie_context"):
        reasons.append(f"cookie context detected ({', '.join((cookie_ctx.get('hits') or [])[:4])})")

    return min(100, max(0, bonus)), reasons

def compute_risk(detections: list[dict], interstitial: bool) -> int:
    # Heuristic semplice: più elementi "cred" + logo => rischio alto
    score = 0
    names = [d["name"] for d in detections]
    # pesi
    weights = {
        "password_field": 25,
        "username_field": 20,
        "login_button": 15,
        "2fa_field": 15,
        "captcha": 10,
        "forgot_password_link": 10,
        "security_alert": 10,
        "fake_certificate": 10,
        "suspicious_banner": 12,
        "remember_me_checkbox": 5,
        "logo_microsoft": 10,
        "logo_google": 10,
        "logo_facebook": 10,
        "logo_paypal": 12,
        "logo_amazon": 10,
        "logo_apple": 10,
        "logo_netflix": 10,
        "logo_instagram": 10,
        "logo_twitter": 10,
        "logo_linkedin": 10,
    }
    for n in set(names):
        score += weights.get(n, 0)

    # bonus se combo classica cred-harvest
    if ("password_field" in names) and ("login_button" in names):
        score += 10
    if ("username_field" in names) and ("password_field" in names):
        score += 10

    # se interstitial Cloudflare suspected phishing => non è "login", ma è un segnale forte di abuso
    if interstitial:
        score += 20

    return max(0, min(100, score))

def save_outputs(out_dir: Path, url: str, meta: dict, detections: list[dict], risk: int, screenshot_path: Path, annotated_path: Path | None, visual_metrics: dict, dom_intel: dict, step2_info: dict, filtered_out_detections: list[dict], *, open_after: bool, save_layout_json: bool = False):
    safe_mkdir(out_dir)
    stamp = now_stamp()
    # JSON report
    import json
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "final_url": meta.get("final_url"),
        "title": meta.get("title"),
        "status_hint": meta.get("status_hint"),
        "interstitial_hint": meta.get("interstitial_hint"),
        "screenshot": str(screenshot_path),
        "annotated_screenshot": str(annotated_path) if annotated_path else None,
        "detections": detections,
        "visual_metrics": visual_metrics,
        "risk": risk,
        "dom_intelligence": dom_intel,
        "step2": step2_info,
        "filtered_detections": filtered_out_detections,
    }
    json_path = out_dir / f"phishradar_{stamp}.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Copia screenshot dentro out_dir con nome stabile (così l'HTML la trova sempre)
    out_png = out_dir / f"phishradar_{stamp}.png"
    try:
        out_png.write_bytes(Path(screenshot_path).read_bytes())
    except Exception:
        pass

    annotated_png = None
    if annotated_path is not None:
        annotated_png = out_dir / f"phishradar_{stamp}_annotated.png"
        try:
            annotated_png.write_bytes(Path(annotated_path).read_bytes())
        except Exception:
            pass

    # HTML mini-dashboard
    rows = "\n".join(
        f"<tr><td>{d['name']}</td><td>{d['conf']:.3f}</td><td>{d['xyxy']}</td></tr>"
        for d in detections
    ) or "<tr><td colspan='3'>(no detections)</td></tr>"


    # palette swatches HTML
    palette = (report.get("visual_metrics", {}) or {}).get("palette_hex", []) or []
    palette_swatches = "".join([f"<span style='width:22px;height:22px;border-radius:6px;border:1px solid #233044;background:{c};display:inline-block' title='{c}'></span>" for c in palette])

    ref_block = ""
    vm = report.get("visual_metrics", {}) or {}
    if vm.get("ref"):
        ref_palette = vm["ref"].get("palette_hex", []) or []
        ref_swatches = "".join([f"<span style='width:22px;height:22px;border-radius:6px;border:1px solid #233044;background:{c};display:inline-block' title='{c}'></span>" for c in ref_palette])
        hs = vm.get("hash_similarity")
        pc = vm.get("position_compare", {})
        lc = vm.get("layout_compare", {}) or {}
        ref_block = f"""
  <div class='small' style='margin-top:14px'><b>Reference compare</b></div>
  <div class='small'>Hash similarity: {hs if hs is not None else ''}</div>
  <div class='small'>YOLO position mismatch: {pc.get('mismatched',0)}/{pc.get('common',0)} (rate {pc.get('mismatch_rate',0)}) tol={pc.get('tol','')}</div>
  <div class='small'>Layout common classes: {lc.get('common_classes', 0)}</div>
  <div class='small'>Layout avg position shift: {lc.get('position_shift_avg', '')}</div>
  <div class='small'>Layout avg size shift: {lc.get('size_shift_avg', '')}</div>
  <div class='small'>Same layout signature: {lc.get('same_signature', False)}</div>
  <div class='small'>Button color distance: {((vm.get("button_color_compare") or {}).get("distance") if vm.get("button_color_compare") else "")}</div>
  <div class='small' style='margin-top:8px'>Palette (ref): {", ".join(ref_palette)}</div>
  <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap">{ref_swatches}</div>
"""

    domi = report.get("dom_intelligence", {}) or {}
    _forms = domi.get("form_actions", []) or []
    _links = domi.get("links", []) or []
    _scripts = domi.get("scripts", []) or []
    dom_form_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_forms[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"
    dom_link_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_links[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"
    dom_script_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_scripts[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"

    annotated_block = ""
    if annotated_png is not None:
        try:
            annotated_block = f"""\n  <div class=\"small\" style=\"margin:14px 0 8px\">Annotato (bbox + cerchi + label)</div>\n  <img src=\"{annotated_png.name}\" alt=\"screenshot annotato\"/>\n"""
        except Exception:
            annotated_block = ""
    html = f"""<!doctype html>
<html lang="it"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ARGUS PhishRadar</title>
<style>
body{{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;margin:24px;background:#0b0f14;color:#e6eef7}}
.card{{background:#121826;border:1px solid #233044;border-radius:14px;padding:16px;box-shadow:0 8px 30px rgba(0,0,0,.35);margin-bottom:16px}}
h1{{margin:0 0 8px 0;font-size:22px}}
.small{{opacity:.85;font-size:13px}}
.badge{{display:inline-block;padding:4px 10px;border-radius:999px;background:#1a2636;border:1px solid #2a3b52;margin-right:8px}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #233044;font-size:13px}}
.risk{{font-size:28px;font-weight:700}}
img{{max-width:100%;border-radius:12px;border:1px solid #233044}}
</style></head>
<body>
<div class="card">
  <h1>ARGUS PhishRadar — Visual Phishing Detection Engine</h1>
  <div class="small">By Neurone4444 · Generated: {report['generated']}</div>
</div>

<div class="card">
  <div class="badge">URL</div> <span class="small">{url}</span><br/>
  <div class="badge">Final</div> <span class="small">{report.get('final_url') or ''}</span><br/>
  <div class="badge">Title</div> <span class="small">{report.get('title') or ''}</span><br/>
  <div class="badge">Status hint</div> <span class="small">{report.get('status_hint')}</span><br/>
  <div class="badge">Interstitial</div> <span class="small">{'YES' if report.get('interstitial_hint') else 'NO'}</span><br/>
  <div style="margin-top:10px" class="risk">Risk: {risk}/100</div>
</div>


<div class="card">
  <h1>Visual Metrics</h1>
  <div class="small">Palette (screenshot): {", ".join(report.get("visual_metrics", {}).get("palette_hex", []) or [])}</div>
  <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap">
    {palette_swatches}
  </div>
  <div class="small" style="margin-top:10px">aHash: {report.get("visual_metrics", {}).get("ahash") or ""}</div>
  <div class="small" style="margin-top:10px">CLIP brand: {((report.get("visual_metrics", {}).get("clip_brand") or {}).get("top_brand") or "")} (score {((report.get("visual_metrics", {}).get("clip_brand") or {}).get("top_score") or "")})</div>
  <div class="small" style="margin-top:10px">Brand-domain mismatch: {((report.get("visual_metrics", {}).get("brand_domain_mismatch")) if "brand_domain_mismatch" in (report.get("visual_metrics", {}) or {}) else "")}</div>
  <div class="small" style="margin-top:10px">DOM/Visual mapping: score {((report.get("visual_metrics", {}).get("dom_visual_mapping") or {}).get("score") or "")}, missing {((report.get("visual_metrics", {}).get("dom_visual_mapping") or {}).get("missing_in_dom") or [])}</div>
  <div class="small" style="margin-top:10px">Layout fingerprint: {((report.get("visual_metrics", {}).get("layout_fingerprint") or {}).get("signature") or "")}</div>
  <div class="small" style="margin-top:6px; word-break:break-all">Layout summary: {((report.get("visual_metrics", {}).get("layout_fingerprint") or {}).get("summary") or "")}</div>
  <div class="small" style="margin-top:10px">Risk drivers: {", ".join(report.get("visual_metrics", {}).get("risk_drivers", []) or [])}</div>
  {ref_block}
</div>

<div class="card">
  <h1>Screenshot</h1>
  <div class="small" style="margin-bottom:8px">Originale</div>
  <img src="{out_png.name}" alt="screenshot originale"/>
  {annotated_block}
</div>

<div class="card">
  <h1>Detections</h1>
  <table>
    <thead><tr><th>Class</th><th>Conf</th><th>Box (xyxy)</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<div class="card">
  <h1>DOM Intelligence</h1>
  <div class="small"><b>Input types:</b> {", ".join((report.get("dom_intelligence", {}) or {}).get("input_types", []) or [])}</div>
  <div class="small" style="margin-top:8px"><b>Form actions:</b></div>
  <table>
    <thead><tr><th>#</th><th>Action</th></tr></thead>
    <tbody>{dom_form_rows}</tbody>
  </table>
  <div class="small" style="margin-top:10px"><b>Links:</b></div>
  <table>
    <thead><tr><th>#</th><th>Href</th></tr></thead>
    <tbody>{dom_link_rows}</tbody>
  </table>
  <div class="small" style="margin-top:10px"><b>Scripts:</b></div>
  <table>
    <thead><tr><th>#</th><th>Src</th></tr></thead>
    <tbody>{dom_script_rows}</tbody>
  </table>
</div>

<div class="small">Tip: se vedi (no detections) prova --width 1366 --height 768 --fullpage --wait 3 --no-headless</div>
</body></html>
"""
    html_path = out_dir / f"phishradar_{stamp}.html"
    html_path.write_text(html, encoding="utf-8")



    layout_json_path = None
    if save_layout_json:
        try:
            layout_report = {
                "generated": report["generated"],
                "url": url,
                "final_url": meta.get("final_url"),
                "title": meta.get("title"),
                "status_hint": meta.get("status_hint"),
                "risk": risk,
        "dom_intelligence": dom_intel,
        "step2": step2_info,
        "filtered_detections": filtered_out_detections,
                "layout_fingerprint": (visual_metrics or {}).get("layout_fingerprint"),
                "clip_brand": (visual_metrics or {}).get("clip_brand"),
                "palette_hex": (visual_metrics or {}).get("palette_hex"),
                "ahash": (visual_metrics or {}).get("ahash"),
                "reference_compare": {
                    "position_compare": (visual_metrics or {}).get("position_compare"),
                    "layout_compare": (visual_metrics or {}).get("layout_compare"),
                    "button_color_compare": (visual_metrics or {}).get("button_color_compare"),
                    "ref": ((visual_metrics or {}).get("ref") or {}),
                },
                "dom_visual_mapping": (visual_metrics or {}).get("dom_visual_mapping"),
                "brand_domain_mismatch": (visual_metrics or {}).get("brand_domain_mismatch"),
                "risk_drivers": (visual_metrics or {}).get("risk_drivers"),
            }
            layout_json_path = out_dir / f"layout_fingerprint_{stamp}.json"
            layout_json_path.write_text(json.dumps(layout_report, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            layout_json_path = None

    print(f"\nSaved:\n  JSON: {json_path}\n  HTML: {html_path}\n  PNG:  {out_png}" + (f"\n  ANNOTATED: {annotated_png}" if annotated_png else "") + (f"\n  LAYOUT_JSON: {layout_json_path}" if layout_json_path else ""))
    if open_after:
        try:
            webbrowser.open(str(html_path.resolve()))
        except Exception:
            pass

def parse_args():
    ap = argparse.ArgumentParser(description="ARGUS PhishRadar Phishing Scanner (NO-API)")
    ap.add_argument("--url", required=True, help="URL da analizzare (live)")
    ap.add_argument("--yolo-model", default=str(DEFAULT_MODEL), help=f"Path al modello YOLO (.pt) addestrato (default: {DEFAULT_MODEL})")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUTPUT), help=f"Cartella output (default: {DEFAULT_OUTPUT})")
    ap.add_argument("--headless", action="store_true", help="Esegue browser in headless (default: false)")
    ap.add_argument("--no-headless", action="store_true", help="Forza headless=false (utile per siti anti-bot)")
    ap.add_argument("--wait", type=float, default=2.5, help="Secondi di attesa dopo DOMContentLoaded (default 2.5)")
    ap.add_argument("--fullpage", action="store_true", help="Screenshot full page (scroll) (default false)")
    ap.add_argument("--width", type=int, default=1366, help="Viewport width (default 1366)")
    ap.add_argument("--height", type=int, default=768, help="Viewport height (default 768)")
    ap.add_argument("--ua", default=None, help="User-Agent custom (string)")
    ap.add_argument("--imgsz", type=int, default=640, help="YOLO imgsz (default 640)")
    ap.add_argument("--ref-url", default=None, help="URL di riferimento (originale) per confronto visivo")
    ap.add_argument("--ref-image", default=None, help="PNG/JPG di riferimento locale per confronto visivo")
    ap.add_argument("--palette-k", type=int, default=6, help="Numero colori palette (default 6)")
    ap.add_argument("--pos-tol", type=float, default=0.06, help="Tolleranza mismatch posizioni (0-1, default 0.06)")
    ap.add_argument("--clip", action="store_true", help="Abilita CLIP brand recognition (richiede transformers/torch)")
    ap.add_argument("--clip-brands", default="Microsoft,Google,Apple,Facebook,Instagram,PayPal,Amazon,Netflix,LinkedIn,X,Twitter", help="Lista brand separati da virgola")
    ap.add_argument("--clip-threshold", type=float, default=0.30, help="Soglia score CLIP per considerare un brand (default 0.30)")
    ap.add_argument("--clip-device", default="cpu", choices=["cpu","cuda"], help="Device CLIP (cpu/cuda)")
    ap.add_argument("--print-layout", action="store_true", help="Stampa fingerprint layout in console")
    ap.add_argument("--save-layout-json", action="store_true", help="Salva anche un file layout_fingerprint_*.json separato")
    ap.add_argument("--filter-anomalous-boxes", action="store_true", help="Filtra bbox anomale (es. falsi positivi enormi su header/banner)")
    ap.add_argument("--step2-email", default=None, help="Email fake da inserire per forzare il secondo step di login, se presente")
    ap.add_argument("--step2-click-selectors", default="button[type=submit],input[type=submit],#idSIButton9,text=Next,text=Avanti,text=Sign in", help="Selettori o testi da provare per avanzare allo step 2")
    ap.add_argument("--brand-allowlist", default=None, help="Domini ufficiali extra separati da virgola per il controllo brand-domain mismatch")
    ap.add_argument("--conf", type=float, default=0.25, help="YOLO conf threshold (default 0.25)")
    ap.add_argument("--iou", type=float, default=0.45, help="YOLO IoU threshold (default 0.45)")
    ap.add_argument("--open", action="store_true", help="Apre la dashboard HTML al termine")
    return ap.parse_args()


def hard_dom_gate_false_positives(detections: list[dict], dom_intel: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    """
    Sopprime detection login-like quando il DOM non contiene un vero password field.
    Utile per ridurre falsi positivi su siti corporate/industriali dove YOLO vede
    pannelli, widget o elementi grafici come campi login.
    """
    dom_intel = dom_intel or {}
    dom_inputs = [str(x).lower() for x in (dom_intel.get("input_types") or [])]

    info = {
        "active": False,
        "reason": None,
        "dom_inputs": dom_inputs,
    }

    # Se esiste una password reale nel DOM, non sopprimere nulla
    if "password" in dom_inputs:
        return detections, [], info

    suppressible = {
        "username_field",
        "password_field",
        "login_button",
        "remember_me_checkbox",
        "forgot_password_link",
    }

    kept = []
    suppressed = []
    for d in detections:
        name = str(d.get("name", ""))
        if name in suppressible:
            suppressed.append({**d, "filtered_reason": "hard_dom_gate_no_password"})
        else:
            kept.append(d)

    if suppressed:
        info["active"] = True
        info["reason"] = "no password field in DOM"

    return kept, suppressed, info


def main():
    banner()
    args = parse_args()

    model_path = Path(args.yolo_model)
    if not model_path.exists():
        print(f"❌ YOLO model not found: {model_path}")
        print("Place your model at models/best.pt or pass --yolo-model <path>")
        return 2

    headless = True if args.headless else False
    if args.no_headless:
        headless = False

    out_dir = Path(args.out_dir)
    safe_mkdir(out_dir)

    # screenshot temp
    tmp_png = Path(tempfile.gettempdir()) / f"argus_phishradar_{now_stamp()}.png"
    annotated_tmp = None  # always defined (anche se annotazione non disponibile)
    visual_metrics = {}
    step2_info = {}
    filtered_out_detections = []
    print(f"Opening: {args.url}")

    meta, dom_intel, step2_info = capture_live_session(
        args.url, tmp_png,
        headless=headless,
        width=args.width,
        height=args.height,
        wait=args.wait,
        fullpage=args.fullpage,
        user_agent=args.ua,
        step2_email=args.step2_email,
        step2_click_selectors=args.step2_click_selectors,
    )
    print(f"Screenshot: {tmp_png}")
    if meta.get("title"):
        print(f"Title: {meta['title']}")
    if meta.get("status_hint") is not None:
        print(f"Status hint: {meta['status_hint']}")
    if meta.get("interstitial_hint"):
        print("⚠️  Interstitial/WAF hint: sembra una pagina di blocco (es. Cloudflare 'Suspected Phishing').")

    # YOLO
    results = run_yolo(args.yolo_model, str(tmp_png), imgsz=args.imgsz, conf=args.conf, iou=args.iou)

    detections = []
    for r in results:
        names = r.names if hasattr(r, "names") else {}
        boxes = getattr(r, "boxes", None)
        if boxes is None:
            continue
        for b in boxes:
            cls_id = int(b.cls.item()) if hasattr(b.cls, "item") else int(b.cls)
            conf = float(b.conf.item()) if hasattr(b.conf, "item") else float(b.conf)
            xyxy = b.xyxy[0].tolist() if hasattr(b.xyxy[0], "tolist") else list(map(float, b.xyxy[0]))
            name = names.get(cls_id, str(cls_id))
            detections.append({"name": name, "conf": conf, "xyxy": [round(x, 2) for x in xyxy]})

    detections.sort(key=lambda x: x["conf"], reverse=True)

    if getattr(args, "filter_anomalous_boxes", False):
        detections, filtered_out_detections = filter_anomalous_detections(detections, width=args.width, height=args.height)
        if filtered_out_detections:
            print(f"Filtered anomalous detections: {len(filtered_out_detections)}")
    detections, filtered_out = filter_suspicious_large_boxes(detections, args.width, args.height)
    if filtered_out:
        visual_metrics["filtered_out"] = filtered_out

    detections, cookie_suppressed, cookie_ctx = suppress_cookie_banner_false_positives(detections, dom_intel=dom_intel, meta=meta)
    if cookie_suppressed:
        filtered_out_detections.extend(cookie_suppressed)
        visual_metrics["cookie_suppressed"] = cookie_suppressed
        print(f"Suppressed cookie-banner false positives: {len(cookie_suppressed)}")
    visual_metrics["cookie_banner_context"] = cookie_ctx

    detections, dom_gate_suppressed, dom_gate_info = hard_dom_gate_false_positives(detections, dom_intel=dom_intel)
    if dom_gate_suppressed:
        filtered_out_detections.extend(dom_gate_suppressed)
        visual_metrics["dom_gate_suppressed"] = dom_gate_suppressed
        print(f"Suppressed DOM-gated login false positives: {len(dom_gate_suppressed)}")
    visual_metrics["hard_dom_gate"] = dom_gate_info

    print("\nDetections")
    print("-" * 40)
    if not detections:
        print("(no detections)")
        print("\nTip rapidi se ti aspetti detection ma non arrivano:")
        print("  • prova DESKTOP: --width 1366 --height 768")
        print("  • prova fullpage: --fullpage")
        print("  • aumenta attesa: --wait 3.5")
        print("  • prova non-headless: --no-headless")
        print("  • se il sito è 'mobile-only' prova 390x844: --width 390 --height 844")
        print("  • se vedi pagina di blocco Cloudflare, è normale che YOLO non veda la UI del phishing.")
    else:
        for d in detections:
            print(f"{d['name']:<22} {d['conf']:.3f}  {d['xyxy']}")

    if detections:
        annotated_tmp = Path(tempfile.gettempdir()) / f"argus_phishradar_annotated_{now_stamp()}.png"
        ok = annotate_screenshot(tmp_png, detections, annotated_tmp)
        if not ok:
            annotated_tmp = None
    else:
        annotated_tmp = None

    # ----------------------------
    # Metriche visive (palette/hash + confronto opzionale)
    # ----------------------------
    try:
        visual_metrics["palette_hex"] = compute_palette(tmp_png, k=int(getattr(args, "palette_k", 6)))
        visual_metrics["ahash"] = compute_ahash(tmp_png)
        visual_metrics["layout_fingerprint"] = build_layout_fingerprint(detections, width=args.width, height=args.height)
        visual_metrics["dom_visual_mapping"] = dom_visual_mapping(meta, detections, args.width, args.height)

        # CLIP brand recognition (opzionale)
        if getattr(args, "clip", False):
            brands = [b.strip() for b in str(getattr(args, "clip_brands", "")).split(",") if b.strip()]
            clip_res = clip_brand_recognition(tmp_png, brands, device=str(getattr(args, "clip_device", "cpu")))
            visual_metrics["clip_brand"] = clip_res
            if clip_res.get("available"):
                tb = clip_res.get("top_brand")
                ts = clip_res.get("top_score") or 0.0
                th = float(getattr(args, "clip_threshold", 0.30))
                if tb and ts >= th:
                    # bonus rischio se ci sono indicatori cred-harvest e brand forte
                    names = [d.get("name") for d in detections]
                    if ("login_button" in names) and (("username_field" in names) or ("password_field" in names)):
                        visual_metrics["clip_risk_bonus"] = 15
                    else:
                        visual_metrics["clip_risk_bonus"] = 7
                else:
                    visual_metrics["clip_risk_bonus"] = 0
            else:
                visual_metrics["clip_risk_bonus"] = 0

    except Exception:
        pass

    # Se fornito un riferimento (URL o immagine), facciamo un confronto
    ref_path = None
    if getattr(args, "ref_image", None):
        rp = Path(args.ref_image)
        if rp.exists():
            ref_path = rp
        else:
            print(f"⚠️  ref-image non trovato: {rp}")
    elif getattr(args, "ref_url", None):
        try:
            ref_tmp = Path(tempfile.gettempdir()) / f"argus_yolo_ref_{now_stamp()}.png"
            print(f"Opening REF: {args.ref_url}")
            _ = take_screenshot_playwright(
                args.ref_url, ref_tmp,
                headless=headless,
                width=args.width,
                height=args.height,
                wait=args.wait,
                fullpage=args.fullpage,
                user_agent=args.ua,
            )
            ref_path = ref_tmp
            print(f"REF Screenshot: {ref_tmp}")
        except Exception as e:
            print(f"⚠️  Impossibile acquisire ref-url: {e}")
            ref_path = None

    if ref_path is not None:
        try:
            # YOLO sul riferimento
            ref_results = run_yolo(args.yolo_model, str(ref_path), imgsz=args.imgsz, conf=args.conf, iou=args.iou)
            ref_dets = []
            for r in ref_results:
                names = r.names if hasattr(r, "names") else {}
                boxes = getattr(r, "boxes", None)
                if boxes is None:
                    continue
                for b in boxes:
                    cls_id = int(b.cls.item()) if hasattr(b.cls, "item") else int(b.cls)
                    conf = float(b.conf.item()) if hasattr(b.conf, "item") else float(b.conf)
                    xyxy = b.xyxy[0].tolist() if hasattr(b.xyxy[0], "tolist") else list(map(float, b.xyxy[0]))
                    name = names.get(cls_id, str(cls_id))
                    ref_dets.append({"name": name, "conf": conf, "xyxy": [round(x, 2) for x in xyxy]})
            ref_dets.sort(key=lambda x: x["conf"], reverse=True)

            visual_metrics["ref"] = {
                "path": str(ref_path),
                "palette_hex": compute_palette(ref_path, k=int(getattr(args, "palette_k", 6))),
                "ahash": compute_ahash(ref_path),
                "layout_fingerprint": build_layout_fingerprint(ref_dets, width=args.width, height=args.height),
            }
            hd = hamming_hex(visual_metrics.get("ahash"), visual_metrics["ref"].get("ahash"))
            if hd is not None:
                # 8x8 aHash = 64 bit => dist 0..64
                visual_metrics["hash_hamming"] = hd
                visual_metrics["hash_similarity"] = round(1.0 - (hd / 64.0), 3)

            visual_metrics["layout_compare"] = compare_layout_fingerprints(
                visual_metrics.get("layout_fingerprint"),
                (visual_metrics.get("ref") or {}).get("layout_fingerprint"),
            )
            visual_metrics["position_compare"] = compare_yolo_positions(
                detections, ref_dets, w=args.width, h=args.height, tol=float(getattr(args, "pos_tol", 0.06))
            )

            btn_det = best_detection_by_class(detections, "login_button")
            ref_btn_det = best_detection_by_class(ref_dets, "login_button")
            suspect_btn_color = get_avg_color_for_detection(tmp_png, btn_det)
            ref_btn_color = get_avg_color_for_detection(ref_path, ref_btn_det)
            visual_metrics["button_color_compare"] = {
                "suspect": suspect_btn_color,
                "reference": ref_btn_color,
                "distance": color_distance_rgb(suspect_btn_color, ref_btn_color),
            }

            # Piccolo bonus rischio se layout "mismatch" alto (tipico kit phishing che copia male)
            try:
                mr = visual_metrics["position_compare"].get("mismatch_rate", 0.0)
                visual_metrics["layout_mismatch_bonus"] = int(round(min(25, mr * 40)))
            except Exception:
                visual_metrics["layout_mismatch_bonus"] = 0

        except Exception as e:
            print(f"⚠️  Confronto con riferimento fallito: {e}")

    try:
        if getattr(args, "print_layout", False):
            fp = (visual_metrics.get("layout_fingerprint") or {})
            print("\nLayout fingerprint")
            print("-" * 40)
            print(f"Signature: {fp.get('signature')}")
            print(f"Summary  : {fp.get('summary')}")
            dvm = (visual_metrics.get("dom_visual_mapping") or {})
            if dvm.get("available"):
                print(f"DOM map  : score={dvm.get('score')} missing={dvm.get('missing_in_dom')}")
    except Exception:
        pass


    try:
        if step2_info:
            print("\nStep-2 interaction")
            print("-" * 40)
            print(f"Attempted : {step2_info.get('attempted')}")
            print(f"Filled    : {step2_info.get('email_filled')}")
            print(f"Clicked   : {step2_info.get('clicked')}")
            print(f"Title     : {step2_info.get('title')}")
            print(f"Final URL : {step2_info.get('final_url')}")
    except Exception:
        pass

    risk = compute_risk(detections, bool(meta.get("interstitial_hint")))
    try:
        risk = max(0, min(100, int(risk + visual_metrics.get("layout_mismatch_bonus", 0) + visual_metrics.get("clip_risk_bonus", 0))))
    except Exception:
        pass
    ctx_bonus, ctx_reasons = contextual_risk(detections, meta, visual_metrics, dom_intel=dom_intel, custom_allowlist=args.brand_allowlist)
    visual_metrics["contextual_risk_bonus"] = ctx_bonus
    visual_metrics["risk_drivers"] = ctx_reasons
    risk = max(0, min(100, int(risk + ctx_bonus)))

    benign_adjust, benign_reasons = benign_site_adjustment(detections, meta, visual_metrics, dom_intel=dom_intel)
    visual_metrics["benign_adjustment"] = benign_adjust
    visual_metrics["benign_reasons"] = benign_reasons
    risk = max(0, min(100, int(risk + benign_adjust)))
    print(f"\nRisk: {risk}")
    if ctx_reasons:
        print("Risk drivers:")
        for r in ctx_reasons:
            print(f"  - {r}")
    if benign_reasons:
        print("Benign/context adjustments:")
        for r in benign_reasons:
            print(f"  - {r}")
    print()

    save_outputs(out_dir, args.url, meta, detections, risk, tmp_png, annotated_tmp, visual_metrics, dom_intel, step2_info, filtered_out_detections, open_after=args.open, save_layout_json=args.save_layout_json)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())