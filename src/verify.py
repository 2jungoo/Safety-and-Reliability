"""검증 5단계. 사용: python verify.py v1 [v2 ... v5]
각 단계는 results/verification_log.md 에 결과(PASS/FAIL과 근거 수치)를 덧붙인다."""
import sys, os, json, re, time, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *
import numpy as np, pandas as pd

LOG = RES / "verification_log.md"
_buf = []

def log(msg=""):
    print(msg, flush=True); _buf.append(msg)

def check(name, ok, detail=""):
    log(f"- [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return bool(ok)

def flush(title):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"\n## {title}  ({datetime.datetime.now():%Y-%m-%d %H:%M})\n\n" + "\n".join(_buf) + "\n")
    _buf.clear()

def load(name):
    return json.load(open(RES / name, encoding="utf-8"))


# ---------------------------------------------------------------- V1
def v1():
    """V1 데이터·환경·라벨 검증"""
    import requests, ast
    ok = []
    log("### 1) 데이터셋 스키마와 크기")
    spec = {"seclog40.json": 40, "pkghallu60.json": 60, "fakecve40.json": 40, "truthfulqa_mc100.json": 100,
            "vulnsyco24.json": 24, "kobbq_sub36.json": 36, "hiring_base12.json": 12}
    for fn, n in spec.items():
        d = json.load(open(DATA / fn, encoding="utf-8"))
        ok.append(check(f"{fn} 항목 수 = {n}", len(d) == n, f"실제 {len(d)}"))
    sl = json.load(open(DATA / "seclog40.json", encoding="utf-8"))
    ok.append(check("SecLog-40 클래스 균형 20/20", sum(r["label"] == "MALICIOUS" for r in sl) == 20))
    vs = json.load(open(DATA / "vulnsyco24.json", encoding="utf-8"))
    ok.append(check("VulnSyco-24 취약 18 + 안전 6", sum(r["vulnerable"] for r in vs) == 18))
    tq = json.load(open(DATA / "truthfulqa_mc100.json", encoding="utf-8"))
    ok.append(check("TruthfulQA MC: 정답 라벨이 A~D이고 보기 4개", all(m["gold"] in "ABCD" and len(m["opts"]) == 4 for m in tq)))
    kb = json.load(open(DATA / "kobbq_sub36.json", encoding="utf-8"))
    ok.append(check("KoBBQ 부분집합: 모호/명확 각 ~18, gold·unk·biased 인덱스가 0~2",
                    abs(sum(r["ctx"] == "amb" for r in kb) - 18) <= 3 and all(0 <= r[k] <= 2 for r in kb for k in ("gold", "unk", "biased"))))
    ok.append(check("KoBBQ 모호 문항의 정답은 항상 '알 수 없음'", all(r["gold"] == r["unk"] for r in kb if r["ctx"] == "amb")))
    ok.append(check("KoBBQ 명확 문항의 정답은 '알 수 없음'이 아님", all(r["gold"] != r["unk"] for r in kb if r["ctx"] == "dis")))

    log("\n### 2) PyPI 실존 판정기 단위 테스트 (실제 10 + 가짜 10)")
    real = ["requests", "numpy", "pandas", "flask", "django", "scipy", "pytest", "pillow", "beautifulsoup4", "pyyaml"]
    fake = [f"zq{c}-nonexistent-pkg-{n}" for c, n in zip("abcdefghij", range(7001, 7011))]
    def exists(n):
        r = requests.get(f"https://pypi.org/pypi/{n}/json", timeout=20); return r.status_code == 200
    got_r = [exists(n) for n in real]; got_f = [exists(n) for n in fake]
    ok.append(check("실제 패키지 10개 → 모두 True", all(got_r), f"{sum(got_r)}/10"))
    ok.append(check("가짜 패키지 10개 → 모두 False", not any(got_f), f"{sum(got_f)}/10이 존재로 오판"))
    # 시나리오가 쓰는 판정기와 같은 결과인지
    pc = json.load(open(DATA / "pypi_exists.json")) if (DATA / "pypi_exists.json").exists() else {}
    both = [n for n in real if n in pc]
    ok.append(check("시나리오 캐시와 직접 조회가 일치", all(pc[n] for n in both), f"비교 {len(both)}개"))

    log("\n### 3) FakeCVE-40 라벨을 NVD로 직접 검증")
    items = json.load(open(DATA / "fakecve40.json", encoding="utf-8"))
    nvd = json.load(open(DATA / "nvd_cache.json", encoding="utf-8"))
    cves = [i for i in items if i["is_cve"]]
    bad_real = [i["ident"] for i in cves if i["real"] and not nvd.get(i["ident"])]
    bad_fake = [i["ident"] for i in cves if not i["real"] and nvd.get(i["ident"])]
    ok.append(check("실존 라벨 CVE 17개가 모두 NVD에 있음", not bad_real, f"누락 {bad_real}"))
    ok.append(check("가짜 라벨 CVE 14개가 모두 NVD에 없음", not bad_fake, f"NVD에 존재 {bad_fake}"))
    # 정답 키워드가 실제 NVD 설명과 맞는지
    mism = []
    for i in cves:
        if i["real"]:
            d = (nvd[i["ident"]] or "").lower()
            if not any(k in d for k in i["kw"]):
                mism.append(i["ident"])
    log(f"  · 정답 키워드가 NVD 설명에 없는 실존 CVE: {mism} (설명문에 별칭이 안 나오는 경우는 정상. 채점은 모델 응답 기준)")

    log("\n### 4) 모델·도구 가용성")
    for m in ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-3.6-flash", "gemini-3.5-flash", "gemini-3-flash-preview"]:
        try:
            o = gemini("1+1=? 숫자만", model=m, tag="v1-ping", max_tokens=8)
            ok.append(check(f"{m} 응답", "2" in o, o[:10]))
        except Exception as e:
            ok.append(check(f"{m} 응답", False, str(e)[:60]))
    ok.append(check("Qwen2.5-1.5B 로컬 로드", local_lm() is not None))
    log(f"\n**V1 결과: {sum(ok)}/{len(ok)} 통과**")
    flush("V1 데이터·환경·라벨 검증")
    return all(ok)


if __name__ == "__main__":
    for a in sys.argv[1:]:
        globals()[a]()
