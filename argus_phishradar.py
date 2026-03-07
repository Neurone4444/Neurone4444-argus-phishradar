def clean_detections(detections, width=None, height=None):
    """
    Lightweight detection cleaner for ARGUS.
    Filters anomalous YOLO detections before further analysis.
    """

    if not detections:
        return []

    cleaned = []

    for d in detections:
        try:
            conf = float(d.get("confidence", d.get("conf", 0)))

            if conf <= 0 or conf > 1:
                continue

            box = d.get("box") or d.get("bbox")

            if not box or len(box) != 4:
                continue

            x1, y1, x2, y2 = box

            if x2 <= x1 or y2 <= y1:
                continue

            if width and height:
                if x1 < 0 or y1 < 0:
                    continue
                if x2 > width or y2 > height:
                    continue

            cleaned.append(d)

        except Exception:
            continue

    return cleaned
