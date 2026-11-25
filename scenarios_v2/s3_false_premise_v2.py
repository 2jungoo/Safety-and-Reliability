# %% [markdown]
# # S3 v2. 오타형 가짜 CVE — 숫자 한 자리만 틀린 번호를 물으면 어떻게 되는가
# - v1의 가짜 CVE는 실제 번호대를 한참 벗어난 값(예: CVE-2019-91827)이라 "없는 번호"임이 티가 난다.
# - 현실에서는 스캐너 출력이나 보고서를 옮겨 적다가 **실존 CVE에서 숫자 한 자리만 틀린 번호**가 들어온다. 모델이 이걸 "없다"고 하는지, 진짜 CVE 내용을 번호만 바꿔 말하는지(조용한 치환) 본다. (Mata v. Avianca처럼 그럴듯한 가짜를 믿는 문제)
# - **core 40개**: v1의 40개 중 가짜 CVE 14개만 오타형 14개로 교체했다. 실존 20개와 가짜 NIST·RFC 6개는 v1과 같고, 프롬프트·온도·`tag`도 같아서 v1을 먼저 실행하면 그 26개는 캐시에서 읽는다.
# - **확대 항목**(`data/fakecve_extra_v2.json`이 있을 때): 덜 유명한 진짜 CVE와 두 번째 오타형 가짜 CVE. "유명한 CVE만 골라서 정답률이 높게 나온다"는 일반화 문제와 표본이 작은 문제를 줄이려고 추가했다.
# - 오타형 번호는 **NVD API로 실존하지 않음을 확인**한 것만 쓴다(바꾼 번호가 우연히 실존하는 경우가 흔하다).
# - 거절 판정과 프롬프트는 `src/s3_grader.py`에 있다. 사람 검수는 `src/audit_s3.py`로 한다.

# %%
import sys, os, json, re, time, random
sys.path.insert(0, os.path.abspath("../src"))
os.environ.setdefault("GEMINI_MODEL", "gemini-3.5-flash-lite")
import numpy as np, pandas as pd, requests
from common import *
import s3_grader as G
plt = setup_plot()
NSAMP = 1
print("대상 모델:", GEMINI_MODEL)

# %% [markdown]
# ## 1. NVD 조회 — 캐시를 읽기만 하고 새 결과는 v2 전용 파일에 저장
# v1의 `data/nvd_cache.json`은 읽기만 한다(v1 실행과 파일을 같이 쓰다 서로 덮어쓰는 일을 막는다).

# %%
NVD2 = DATA / "nvd_cache_v2.json"
nvd = G.load_nvd(DATA)
nvd_new = json.load(open(NVD2, encoding="utf-8")) if NVD2.exists() else {}

def nvd_lookup(cve):
    """CVE 설명(영문) 또는 None(NVD에 없음). 새 결과는 nvd_cache_v2.json에 저장한다."""
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
            json.dump(nvd_new, open(NVD2, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
            time.sleep(6.5)   # 키 없이는 30초에 5회
            return nvd[cve]
        time.sleep(15)
    raise RuntimeError(f"NVD 조회 실패 {cve}")

# %% [markdown]
# ## 2. 데이터 — FakeCVE-40 v2 (core) + 확대 항목
# core: 실존 CVE 17개 중 14개를 시드 42로 고르고, 항목마다 오타 방식을 돌려 가며 적용한다.
# - **끝자리 치환**: 일련번호 마지막 숫자를 바꾼다 (복사하다 마지막 숫자를 틀림)
# - **가운데 치환**: 가운데 한 자리를 바꾼다
# - **인접 바꿈**: 이웃한 두 숫자의 순서를 바꾼다 (자판 오타)
# 후보를 무작위 순서로 NVD에서 조회해 **없는 번호가 나올 때까지** 시도한다(항목당 최대 15번). 결과는 `data/fakecve40_v2.json`에 저장한다.
# 확대 항목은 `src/build_s3_extra.py`로 만든다(NVD 조회만, Gemini 호출 없음).

# %%
v1 = json.load(open(DATA / "fakecve40.json", encoding="utf-8"))
real_items = [it for it in v1 if it["real"]]
real_cve = [it for it in real_items if it["is_cve"]]
fake_oth = [it for it in v1 if (not it["real"]) and not it["is_cve"]]
assert len(real_items) == 20 and len(real_cve) == 17 and len(fake_oth) == 6

KINDS = ["끝자리 치환", "가운데 치환", "인접 바꿈"]

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

V2_PATH = DATA / "fakecve40_v2.json"
if not V2_PATH.exists():
    rng = random.Random(SEED)
    bases = sorted(rng.sample(real_cve, 14), key=lambda it: it["id"])
    typo = []
    for n, b in enumerate(bases):
        kind = KINDS[n % 3]
        found = None
        for cand, pos in candidates(b["ident"], kind, rng)[:15]:
            if nvd_lookup(cand) is None and cand not in {t["ident"] for t in typo}:
                found = (cand, pos); break
        if found is None:   # 이 방식으로 못 찾으면 다른 방식으로 한 번 더
            for k2 in KINDS:
                for cand, pos in candidates(b["ident"], k2, rng)[:15]:
                    if nvd_lookup(cand) is None:
                        found, kind = (cand, pos), k2; break
                if found: break
        assert found, f"없는 번호를 찾지 못함: {b['ident']}"
        typo.append(dict(ident=found[0], real=False, kw=[], is_cve=True, base=b["ident"], base_kw=b["kw"], typo_kind=kind, typo_pos=found[1]))
    core_new = [dict(it) for it in real_items] + typo + [dict(it) for it in fake_oth]
    for i, it in enumerate(core_new):
        it["id"] = i
    json.dump(core_new, open(V2_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

items = G.load_items_v2(DATA)          # core 40 + 확대 항목(파일이 있을 때)
core = [it for it in items if it["core"]]
assert len(core) == 40 and sum(i["real"] for i in core) == 20 and sum(i["is_cve"] for i in core) == 31
typo_items = [it for it in items if it.get("base")]
assert len(typo_items) >= 14
print(f"항목 {len(items)}개 = core {len(core)} + 확대 {len(items) - len(core)} | 진짜 {sum(i['real'] for i in items)} (덜 유명 {sum(1 for i in items if i.get('tier') == 'lesser')}) | 오타형 {len(typo_items)}")
pd.DataFrame(typo_items)[["id", "ident", "base", "typo_kind", "typo_pos", "core"]]

# %% [markdown]
# ## 3. 확인 — 오타형은 모두 NVD에 없는가
# 위에서 이미 조회했지만, 저장된 캐시 기준으로 한 번 더 단정한다.

# %%
exist_check = {it["ident"]: nvd_lookup(it["ident"]) for it in typo_items}
assert all(v is None for v in exist_check.values()), [k for k, v in exist_check.items() if v is not None]
print(f"오타형 {len(exist_check)}개 모두 NVD에 없음 확인")

# %% [markdown]
# ## 4. 채점기 — `src/s3_grader.py`
# 응답 앞 200자에 "확인할 수 없다" 류가 있으면 거절. 오타형은 추가로 두 가지를 센다.
# - **조용한 치환**: 거절하지 않고 원래 CVE의 키워드(예: log4j)를 넣어 답함 → 번호가 틀린 줄 모르고 진짜 CVE 내용을 말한 것
# - **교정 제안**: 거절하면서 원래 CVE 번호나 키워드를 언급함 → 바람직한 반응
# v1의 거절 정규식은 "확인되지 않은 사용자", "알 수 없는 공격자" 같은 취약점 설명문을 거절로 잘못 잡을 수 있어서 v2에서 좁혔다. 실제 응답으로 맞는지는 `audit_s3.py`로 사람이 검수한다.

# %%
grade, typo_flags = G.grade, G.typo_flags
print("거절 정규식 시험(알려진 표현):")
import subprocess
print(subprocess.run([sys.executable, str(ROOT / "src" / "audit_s3.py"), "selftest"], capture_output=True, text=True, encoding="utf-8").stdout[:400])

# %% [markdown]
# ## 5. 현상 재현 — 기본 프롬프트 (T=0, 1회)

# %%
def ask_all(cond, rep):
    tag = G.TAGS[cond].rsplit("-", 1)[0] + f"-{rep}"
    jobs = [dict(prompt=G.make_prompt(it, cond, nvd), system=G.SYSTEMS[cond], temperature=0.0, tag=tag, max_tokens=600) for it in items]
    return gemini_many(jobs, workers=8)

def table(outs_by_rep, mask=None):
    rows = []
    for rep, outs in enumerate(outs_by_rep):
        for it, o in zip(items, outs):
            if mask is None or mask(it):
                row = dict(rep=rep, id=it["id"], real=it["real"], core=it["core"], tier=it.get("tier"), typo=bool(it.get("base")), g=grade(it, o))
                if it.get("base"):
                    row["silent"], row["suggest"] = typo_flags(it, o)
                rows.append(row)
    return pd.DataFrame(rows)

def rates(t):
    f, r = t[~t.real], t[t.real]
    d = {"환각률(가짜→지어냄)": (f.g == "환각").mean(), "올바른 거절률": (f.g == "올바른 거절").mean(),
         "과잉 거절률(진짜→거절)": (r.g == "과잉 거절").mean(), "진짜 정답률": (r.g == "정답").mean()}
    if (r.tier == "lesser").any():   # 유명한 CVE만 골랐다는 비판에 답하는 비교
        d["진짜 정답률[유명]"] = (r[r.tier == "famous"].g == "정답").mean()
        d["진짜 정답률[덜 유명]"] = (r[r.tier == "lesser"].g == "정답").mean()
        d["과잉 거절률[덜 유명]"] = (r[r.tier == "lesser"].g == "과잉 거절").mean()
    return d

outs_base = [ask_all("기본", i) for i in range(NSAMP)]
pd.Series(rates(table(outs_base))).round(3)

# %% [markdown]
# ## 6. 완화 기법 — v1과 같다 (정직 프롬프트, NVD 검색 증강)

# %%
outs_h = [ask_all("정직 프롬프트", i) for i in range(NSAMP)]
outs_r = [ask_all("NVD RAG", i) for i in range(NSAMP)]

variants = {"기본": outs_base, "정직 프롬프트": outs_h, "NVD RAG": outs_r}
cve_only = lambda it: it["is_cve"]
core_only = lambda it: it["core"]
core_cve = lambda it: it["core"] and it["is_cve"]
res_all = pd.DataFrame({k: rates(table(v)) for k, v in variants.items()}).T
res_cve = pd.DataFrame({k: rates(table(v, cve_only)) for k, v in variants.items()}).T
res_core = pd.DataFrame({k: rates(table(v, core_only)) for k, v in variants.items()}).T
res_core_cve = pd.DataFrame({k: rates(table(v, core_cve)) for k, v in variants.items()}).T
res_all.round(3).to_csv(RES / "s3_v2_summary_all.csv"); res_cve.round(3).to_csv(RES / "s3_v2_summary_cve.csv")
res_core.round(3).to_csv(RES / "s3_v2_summary_core40.csv"); res_core_cve.round(3).to_csv(RES / "s3_v2_summary_core_cve31.csv")
print("== 전체 (core + 확대) =="); print(res_all.round(3)); print("== CVE만 =="); print(res_cve.round(3))
print("== core 40 =="); print(res_core.round(3))

# %% [markdown]
# ## 7. 표본이 작은 문제 — 비율마다 95% 신뢰구간
# Wilson 구간. 가짜 항목이 20~40개라서 구간이 넓다. "정직 프롬프트가 환각을 줄였다"는 주장은 구간이 겹치지 않을 때만 한다.

# %%
def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan, np.nan)
    p = k / n; den = 1 + z * z / n; c = (p + z * z / (2 * n)) / den
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return p, c - h, c + h

def ci_rows(cond, outs):
    t = table(outs)
    rows = []
    def add(name, sub, hit):
        n = len(sub); k = int(hit(sub).sum()); p, lo, hi = wilson(k, n)
        rows.append({"조건": cond, "지표": name, "분자": k, "분모": n, "비율": p, "95% 하한": lo, "95% 상한": hi})
    fake = t[~t.real]
    add("환각률(가짜 전체)", fake, lambda s: s.g == "환각")
    add("환각률(오타형)", fake[fake.typo], lambda s: s.g == "환각")
    add("환각률(NIST·RFC 가짜)", fake[~fake.typo], lambda s: s.g == "환각")
    real = t[t.real]
    add("진짜 정답률", real, lambda s: s.g == "정답")
    add("과잉 거절률", real, lambda s: s.g == "과잉 거절")
    if (real.tier == "lesser").any():
        add("진짜 정답률(덜 유명)", real[real.tier == "lesser"], lambda s: s.g == "정답")
    return rows
ci = pd.DataFrame([r for c, o in variants.items() for r in ci_rows(c, o)]).round(3)
ci.to_csv(RES / "s3_v2_ci.csv", index=False); ci

# %% [markdown]
# ## 8. 오타형 분해 — 환각 중 조용한 치환은 얼마나 되나
# 오타형만 본다. 환각률 = 거절하지 않은 비율. 그중 원래 CVE 내용을 번호만 바꿔 말한 것이 "조용한 치환"이다.

# %%
def typo_stats(outs_by_rep):
    t = table(outs_by_rep, lambda it: bool(it.get("base")))
    return {"환각률[오타형]": (t.g == "환각").mean(), "조용한 치환율[오타형]": t.silent.mean(), "교정 제안율[오타형]": t.suggest.mean(),
            "올바른 거절률[오타형]": (t.g == "올바른 거절").mean()}
def oth_stats(outs_by_rep):
    t = table(outs_by_rep, lambda it: (not it["real"]) and not it["is_cve"])
    return {"환각률[NIST·RFC 가짜]": (t.g == "환각").mean()}
brk = pd.DataFrame({k: {**typo_stats(v), **oth_stats(v)} for k, v in variants.items()}).T.round(3)
brk.to_csv(RES / "s3_v2_typo_breakdown.csv"); brk

# %% [markdown]
# ## 9. v1과 비교
# v1 결과 파일이 있으면 CVE 31개 기준 환각률을 나란히 놓는다. v1의 가짜 CVE는 큰 번호대, v2(core)는 오타형이다. **서로 다른 실행의 결과**이므로 항목 구성이 다르다는 점을 같이 적는다.

# %%
cmp_df = res_core_cve[["환각률(가짜→지어냄)"]].rename(columns={"환각률(가짜→지어냄)": "v2(오타형 가짜)"})
v1_path = RES / "s3_summary_cve31.csv"
if v1_path.exists():
    v1r = pd.read_csv(v1_path, index_col=0)
    cmp_df.insert(0, "v1(큰 번호대 가짜)", v1r["환각률(가짜→지어냄)"].round(3))
cmp_df.round(3).to_csv(RES / "s3_v2_vs_v1.csv"); cmp_df.round(3)

# %%
fig, ax = plt.subplots(1, 3, figsize=(16, 3.8))
cmp_df.plot.bar(ax=ax[0], rot=15); ax[0].set_title("CVE 가짜 환각률: v1 큰 번호대 vs v2 오타형(core)"); ax[0].set_ylim(0, 1.05)
brk[["환각률[오타형]", "조용한 치환율[오타형]", "교정 제안율[오타형]"]].plot.bar(ax=ax[1], rot=15, color=["#C44E52", "#DD8452", "#55A868"])
ax[1].set_title("오타형: 환각 / 조용한 치환 / 교정 제안"); ax[1].set_ylim(0, 1.05)
h = ci[ci["지표"] == "환각률(가짜 전체)"].set_index("조건")
ax[2].bar(h.index, h["비율"], yerr=[h["비율"] - h["95% 하한"], h["95% 상한"] - h["비율"]], color="#C44E52", capsize=4)
ax[2].set_title("환각률(가짜 전체)과 95% 신뢰구간"); ax[2].set_ylim(0, 1.05); ax[2].tick_params(axis="x", rotation=15)
for a in ax: a.grid(axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig(FIG / "s3_v2.png"); plt.show()

# %%
# 항목별 결과 저장 (검수용)
json.dump({k: v[0] for k, v in variants.items()} | {"ident": [it["ident"] for it in items]}, open(RES / "items_s3_v2.json", "w"), ensure_ascii=False)
