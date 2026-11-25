# %% [markdown]
# # S1 v2. 현실 조건 — 악성이 드문 알림 스트림에서 경보의 몇 %가 진짜인가
# - v1(`scenarios/s1_inconsistency.py`)은 악성 20 + 정상 20, 악성 비율 50%에서 정확도를 쟀다. 실제 SOC는 악성이 1~5%다.
# - 같은 모델 응답에서 TPR(악성을 악성으로)과 FPR(정상을 악성으로)을 구한 뒤, **악성 비율 π에 따라 정밀도(경보 중 진짜 비율)가 어떻게 달라지는지** 다시 계산한다.
# - **새 Gemini 호출은 0회다.** v1이 만든 캐시를 읽기만 한다. v1 S1을 먼저 실행해야 한다.
# - 한계: 정상 로그 20개 중 13개가 "공격처럼 보이는 어려운 사례"다. 실제 정상 트래픽은 대부분 쉬우므로 표본 FPR은 현실보다 높다(정밀도는 낮게 나온다). 그래서 어려운 사례 비율을 바꾼 민감도 분석을 같이 한다.

# %%
import sys, os, json
sys.path.insert(0, os.path.abspath("../src"))
os.environ.setdefault("GEMINI_MODEL", "gemini-3.5-flash-lite")   # v1 S1과 같은 모델이어야 캐시가 맞는다
os.environ.setdefault("GEMINI_CACHE_ONLY", "1")                   # 캐시에 없으면 호출하지 않고 멈춘다 (한도 보호)
import numpy as np, pandas as pd
from common import *
plt = setup_plot()
LABELS = ["MALICIOUS", "BENIGN"]
NREP = 3
print("대상 모델:", GEMINI_MODEL, "| 캐시 전용:", os.environ.get("GEMINI_CACHE_ONLY"))

# %% [markdown]
# ## 1. 데이터 — v1이 저장한 SecLog-40

# %%
logs = json.load(open(DATA / "seclog40.json", encoding="utf-8"))
N = len(logs)
assert N == 40
y = np.array([r["label"] for r in logs], dtype=object)
lvl = np.array([r["level"] for r in logs], dtype=object)
is_mal = y == "MALICIOUS"
print("악성", int(is_mal.sum()), "| 정상", int((~is_mal).sum()), "| 정상 중 어려운 사례", int(((~is_mal) & (lvl == "hard")).sum()))

# %% [markdown]
# ## 2. v1과 같은 요청을 캐시에서 읽는다
# 프롬프트·시스템 프롬프트·온도·`tag`가 v1과 한 글자도 달라서는 안 된다(캐시 키에 들어간다). v1 `run()`을 그대로 옮겼다.

# %%
P0 = "다음 보안 로그를 분류해줘. 악성이면 MALICIOUS, 정상이면 BENIGN 중 하나만 답해.\n로그: {log}"
SYS = "너는 SOC 분석가다. 로그 한 줄을 보고 판정한다."

def run(method, rep, tpl=P0, T=1.0):
    jobs = []
    for r in logs:
        pr = tpl.format(log=r["log"])
        if method == "plain":
            jobs.append(dict(prompt=pr, system=SYS, temperature=T, tag=f"s1-{method}-{rep}"))
        elif method == "struct":
            pr += '\n\nJSON으로만 답해: {"evidence":"근거 한 줄","verdict":"MALICIOUS|BENIGN"}'
            jobs.append(dict(prompt=pr, system=SYS, temperature=T, tag=f"s1-{method}-{rep}", max_tokens=200))
    outs = gemini_many(jobs, workers=8)
    if method == "struct":
        return [first_label(o.split('"verdict"')[-1], LABELS, "BENIGN") for o in outs]
    return [first_label(o, LABELS, "BENIGN") for o in outs]

try:
    COND = {
        "baseline (T=1)": [run("plain", i) for i in range(NREP)],
        "T=0": [run("plain", i, T=0.0) for i in range(2)],
        "T=0 + 구조화": [run("struct", i, T=0.0) for i in range(2)],
    }
except RuntimeError as e:
    raise RuntimeError("v1 S1(scenarios/s1_inconsistency.py)을 먼저 실행해 캐시를 채운 뒤 다시 실행하세요. 원인: " + str(e))
COND = {k: np.array(v, dtype=object) for k, v in COND.items()}   # (실행 횟수, N)
print({k: v.shape for k, v in COND.items()})

# %% [markdown]
# ## 3. 악성 비율 π에 따른 정밀도
# `정밀도 = TPR·π / (TPR·π + FPR·(1−π))`. 신뢰구간은 악성 항목과 정상 항목을 따로 부트스트랩(2,000회)해서 구한다.
# 알림 1,000건 가정은 설명을 위한 가정이다.

# %%
PIS = [0.01, 0.05, 0.20, 0.50]
NALERT = 1000

def tpr_fpr(A, idx_m=None, idx_b=None):
    m = np.where(is_mal)[0] if idx_m is None else idx_m
    b = np.where(~is_mal)[0] if idx_b is None else idx_b
    return (A[:, m] == "MALICIOUS").mean(), (A[:, b] == "MALICIOUS").mean()

def ppv(tpr, fpr, pi):
    den = tpr * pi + fpr * (1 - pi)
    return tpr * pi / den if den > 0 else np.nan

rng = np.random.RandomState(SEED)
mal_idx, ben_idx = np.where(is_mal)[0], np.where(~is_mal)[0]
BOOT = [(rng.choice(mal_idx, len(mal_idx)), rng.choice(ben_idx, len(ben_idx))) for _ in range(2000)]

rows = []
for name, A in COND.items():
    tpr, fpr = tpr_fpr(A)
    bt = np.array([tpr_fpr(A, m, b) for m, b in BOOT])
    for pi in PIS:
        p = ppv(tpr, fpr, pi)
        pb = np.array([ppv(t, f, pi) for t, f in bt])
        lo, hi = np.nanpercentile(pb, [2.5, 97.5])
        tp = NALERT * pi * tpr; fn = NALERT * pi * (1 - tpr); fp = NALERT * (1 - pi) * fpr
        rows.append({"조건": name, "악성 비율 π": pi, "TPR": tpr, "FPR(표본)": fpr, "정밀도": p, "정밀도 95% 하한": lo, "정밀도 95% 상한": hi,
                     "알림 1000건 중 진짜 경보": tp, "오탐 경보": fp, "놓친 공격": fn})
prev = pd.DataFrame(rows).round(3)
prev.to_csv(RES / "s1_v2_prevalence.csv", index=False)
prev

# %% [markdown]
# ## 4. 민감도 — 정상 로그 중 "어려운 사례" 비율을 바꾸면
# 표본의 정상 로그는 어려운 사례가 13/20(65%)이다. 실제 정상 트래픽의 어려운 사례 비율 h를 10%, 1%로 가정하면 FPR은 `h·FPR(어려움) + (1−h)·FPR(쉬움)`이 된다. 쉬운 정상 로그가 7개뿐이라 FPR(쉬움)의 불확실성이 크다.

# %%
hard_b = np.where((~is_mal) & (lvl == "hard"))[0]
easy_b = np.where((~is_mal) & (lvl == "easy"))[0]
rows = []
for name, A in COND.items():
    tpr, _ = tpr_fpr(A)
    f_hard = (A[:, hard_b] == "MALICIOUS").mean(); f_easy = (A[:, easy_b] == "MALICIOUS").mean()
    for h in [0.65, 0.10, 0.01]:
        fpr_mix = h * f_hard + (1 - h) * f_easy
        rows.append({"조건": name, "정상 중 어려운 사례 비율 h": h, "FPR(어려움)": f_hard, "FPR(쉬움)": f_easy, "FPR(가정)": fpr_mix,
                     "정밀도(π=5%)": ppv(tpr, fpr_mix, 0.05), "정밀도(π=1%)": ppv(tpr, fpr_mix, 0.01)})
sens = pd.DataFrame(rows).round(3)
sens.to_csv(RES / "s1_v2_sensitivity.csv", index=False)
sens

# %% [markdown]
# ## 5. 비교·해석

# %%
fig, ax = plt.subplots(1, 2, figsize=(13, 3.8))
pv = prev.pivot(index="악성 비율 π", columns="조건", values="정밀도")
pv.index = [f"{int(p*100)}%" for p in pv.index]
pv.plot.bar(ax=ax[0], rot=0); ax[0].set_title("악성 비율별 정밀도 (경보 중 진짜 비율)"); ax[0].set_ylim(0, 1.05); ax[0].set_xlabel("악성 비율 π")
sv = sens.pivot(index="정상 중 어려운 사례 비율 h", columns="조건", values="정밀도(π=5%)")
sv.index = [f"h={int(round(h*100))}%" for h in sv.index]
sv.plot.bar(ax=ax[1], rot=0); ax[1].set_title("π=5%에서 정상 로그 난이도 가정별 정밀도"); ax[1].set_ylim(0, 1.05)
for a in ax: a.grid(axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig(FIG / "s1_v2.png"); plt.show()
