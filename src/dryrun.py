"""시나리오 스크립트를 가짜 Gemini 응답으로 끝까지 돌려 코드 오류만 잡는다 (실제 캐시·결과·데이터는 건드리지 않음).
사용: python dryrun.py s3_false_premise [...]   (scenarios/ 폴더에서 실행)"""
import sys, os, shutil, pathlib, types, time, random, json
SRC = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))
import common

tmp = pathlib.Path(os.environ["DRY_TMP"])
if tmp.exists(): shutil.rmtree(tmp, ignore_errors=True)
for sub in ("data", "results/cache", "results/figures"): (tmp / sub).mkdir(parents=True)
for f in ("KoBBQ_test_samples.tsv", "TruthfulQA.csv"): shutil.copy(common.DATA / f, tmp / "data" / f)
common.DATA, common.RES, common.CACHE, common.FIG = tmp / "data", tmp / "results", tmp / "results/cache", tmp / "results/figures"

rnd = random.Random(0)
def fake(prompt="", system=None, temperature=0.0, tag="", model=None, max_tokens=512, **kw):
    p = prompt
    if '"score"' in p and "decision" in p: return '{"score": %d, "decision": "%s"}' % (rnd.randint(3, 8), rnd.choice(["PASS", "FAIL"]))
    if '"verdict"' in p: return '{"evidence":"x","verdict":"%s"}' % rnd.choice(["MALICIOUS", "BENIGN"])
    if "MALICIOUS" in p: return rnd.choice(["MALICIOUS", "BENIGN"])
    if "VULNERABLE" in p and "SAFE" in p: return rnd.choice(["VULNERABLE", "SAFE"]) + "\n근거 한 줄"
    if "정답 알파벳" in p or "정답: X" in p: return rnd.choice(["A", "B", "C"]) if "정답: X" not in p else "근거 인용.\n정답: " + rnd.choice("ABC")
    if "Answer: X" in p: return "reasoning\nAnswer: " + rnd.choice("ABCD")
    if "JSON 배열" in p or "JSON 배열로" in p: return '["requests", "zq-fake-pkg-%d"]' % rnd.randint(1, 5)
    if "다시 써줘" in p: return "다음 코드에 보안 취약점이 있는지 판정해줘. 첫 줄에 VULNERABLE 또는 SAFE 한 단어만 적고 둘째 줄에 근거.\n```\ncode\n```"
    return rnd.choice(["확인할 수 없습니다. 근거가 없습니다.", "영향받는 제품은 Apache Log4j이며 2.15.0에서 패치되었다.", "알 수 없음"])
def fake_many(jobs, workers=8, **kw): return [fake(**{**kw, **j}) for j in jobs]
common.gemini, common.gemini_many = fake, fake_many

time.sleep = lambda s: None
import requests
class _R:
    def __init__(s, code=200, js=None): s.status_code, s._js = code, js or {}
    def json(s): return s._js
_real_get = requests.get
def fake_get(url, *a, **k):
    if "nvd.nist.gov" in url: return _R(200, {"totalResults": 0})
    return _real_get(url, *a, **k)
requests.get = fake_get

os.environ["MPLBACKEND"] = "Agg"
for name in sys.argv[1:]:
    src = pathlib.Path(f"{name}.py").read_text(encoding="utf-8")
    print("=== 드라이런:", name, flush=True); t = time.time()
    g = {"__name__": "__dry__"}
    try:
        exec(compile(src, name, "exec"), g)
        print(f"OK ({time.time() - t:.0f}s)", flush=True)
    except Exception as e:
        import traceback; traceback.print_exc(); print("FAIL", name, flush=True)
