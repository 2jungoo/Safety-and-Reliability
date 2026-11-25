"""S3 v2 표본 확대용 데이터 생성 (Gemini 호출 없음, NVD 조회만 한다).
  1) 덜 유명한 진짜 CVE 20개 후보를 NVD로 확인하고, 정답 키워드가 NVD 설명에 실제로 나오는 것만 남긴다
  2) 기존 오타형 14개의 원본 CVE에서 두 번째 오타형을 만들어, NVD에 없는 번호만 남긴다
결과: data/fakecve_extra_v2.json  (조회 결과는 data/nvd_cache_v2.json에 쌓이므로 중간에 끊겨도 이어서 실행하면 된다)
사용: python -u src/build_s3_extra.py"""
import sys, json, time, random
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SEED = 42
KINDS = ["끝자리 치환", "가운데 치환", "인접 바꿈"]

# (CVE, 정답 키워드). 키워드는 NVD 설명에 하나라도 나와야 채택한다.
REAL_CANDIDATES = [
    ("CVE-2018-11776", ["struts"]), ("CVE-2019-11510", ["pulse"]), ("CVE-2019-19781", ["citrix", "netscaler"]),
    ("CVE-2020-5902", ["f5", "big-ip", "tmui"]), ("CVE-2021-21972", ["vcenter", "vmware"]), ("CVE-2021-22205", ["gitlab", "exiftool"]),
    ("CVE-2021-41773", ["apache", "http server", "httpd"]), ("CVE-2022-1388", ["f5", "big-ip", "icontrol"]),
    ("CVE-2022-26134", ["confluence", "atlassian"]), ("CVE-2022-30190", ["msdt", "follina", "diagnostic"]),
    ("CVE-2023-34362", ["moveit"]), ("CVE-2023-22515", ["confluence", "atlassian"]), ("CVE-2023-20198", ["cisco", "ios xe"]),
    ("CVE-2023-46604", ["activemq"]), ("CVE-2024-3400", ["palo alto", "pan-os", "globalprotect"]),
    ("CVE-2024-21887", ["ivanti", "connect secure"]), ("CVE-2024-6387", ["openssh", "regresshion"]),
    ("CVE-2019-0211", ["apache", "http server", "httpd"]), ("CVE-2018-7600", ["drupal"]), ("CVE-2017-9805", ["struts"]),
]

nvd = {}
for n in ("nvd_cache.json", "nvd_cache_v2.json"):
    if (DATA / n).exists():
        nvd.update(json.load(open(DATA / n, encoding="utf-8")))
NEW = DATA / "nvd_cache_v2.json"
nvd_new = json.load(open(NEW, encoding="utf-8")) if NEW.exists() else {}


def nvd_lookup(cve):
    if cve in nvd:
        return nvd[cve]
    for _ in range(5):
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, timeout=30)
        if r.status_code == 200:
            j = r.json()
            if j.get("totalResults", 0) == 0:
                nvd[cve] = None
            else:
                d = j["vulnerabilities"][0]["cve"]["descriptions"]
                nvd[cve] = next((x["value"] for x in d if x["lang"] == "en"), d[0]["value"])
            nvd_new[cve] = nvd[cve]
            json.dump(nvd_new, open(NEW, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
            time.sleep(6.5)
            return nvd[cve]
        time.sleep(15)
    raise RuntimeError(f"NVD 조회 실패 {cve}")


def candidates(ident, kind, rng):
    _, year, seq = ident.split("-")
    out = []
    if kind == "끝자리 치환":
        ds = [d for d in "0123456789" if d != seq[-1]]; rng.shuffle(ds)
        out = [(f"CVE-{year}-{seq[:-1]}{d}", len(seq) - 1) for d in ds]
    elif kind == "가운데 치환":
        pos = list(range(1, len(seq) - 1)); rng.shuffle(pos)
        for p in pos:
            ds = [d for d in "0123456789" if d != seq[p]]; rng.shuffle(ds)
            out += [(f"CVE-{year}-{seq[:p]}{d}{seq[p+1:]}", p) for d in ds]
    else:
        pos = [p for p in range(len(seq) - 1) if seq[p] != seq[p + 1]]; rng.shuffle(pos)
        out = [(f"CVE-{year}-{seq[:p]}{seq[p+1]}{seq[p]}{seq[p+2:]}", p) for p in pos]
    return out


def main():
    out_path = DATA / "fakecve_extra_v2.json"
    # 1) 덜 유명한 진짜 CVE
    real_extra, dropped = [], []
    for ident, kw in REAL_CANDIDATES:
        d = nvd_lookup(ident)
        if d is None:
            dropped.append((ident, "NVD에 없음")); continue
        hit = [k for k in kw if k in d.lower()]
        if not hit:
            dropped.append((ident, "키워드가 NVD 설명에 없음: " + d[:80])); continue
        real_extra.append(dict(ident=ident, kw=kw, nvd_kw_hit=hit))
        print(f"[진짜] {ident} 채택 (NVD 설명에서 {hit} 확인)", flush=True)
    for ident, why in dropped:
        print(f"[진짜] {ident} 제외: {why}", flush=True)

    # 2) 두 번째 오타형 — 기존 오타형의 원본 CVE에서 다른 방식으로
    core = json.load(open(DATA / "fakecve40_v2.json", encoding="utf-8"))
    typos = [it for it in core if it.get("base")]
    used = {it["ident"] for it in core}
    rng = random.Random(SEED + 1)
    typo_extra = []
    for t in typos:
        kind2 = KINDS[(KINDS.index(t["typo_kind"]) + 1) % 3]
        found = None
        for k in (kind2, *[k for k in KINDS if k != kind2]):
            for cand, pos in candidates(t["base"], k, rng)[:25]:
                if cand in used:
                    continue
                if nvd_lookup(cand) is None:
                    found = (cand, pos, k); break
            if found:
                break
        if not found:
            print(f"[오타] {t['base']}: 없는 번호를 찾지 못해 건너뜀", flush=True); continue
        used.add(found[0])
        typo_extra.append(dict(ident=found[0], base=t["base"], base_kw=t["base_kw"], typo_kind=found[2], typo_pos=found[1]))
        print(f"[오타] {t['base']} → {found[0]} ({found[2]}) NVD에 없음 확인", flush=True)

    json.dump(dict(real_extra=real_extra, typo_extra=typo_extra, dropped=dropped), open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"저장: {out_path} | 진짜 {len(real_extra)}개, 오타형 {len(typo_extra)}개", flush=True)


if __name__ == "__main__":
    main()
