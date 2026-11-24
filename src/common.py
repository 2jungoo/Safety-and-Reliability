"""공통 유틸: Gemini 호출(JSONL 캐시), 로컬 Qwen, 통계 함수.
재실행 시 캐시만 읽으므로 API 호출 없이 같은 결과가 나온다."""
import os, json, time, hashlib, random, threading
os.environ.setdefault("USE_TF", "0"); os.environ.setdefault("TRANSFORMERS_NO_TF", "1")  # TF/Keras3 충돌 방지
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
from pathlib import Path
_lock = threading.Lock()
MISSES = {}
import atexit
atexit.register(lambda: MISSES and print("[캐시 미스]", {m: len(s) for m, s in MISSES.items()}, flush=True))
import numpy as np

SEED = 42
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RES = ROOT / "results"
CACHE = RES / "cache"
FIG = RES / "figures"
for p in (DATA, RES, CACHE, FIG):
    p.mkdir(parents=True, exist_ok=True)

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")  # 주 대상 (2025-26 기준 사용 가능 확인)
GEMINI_MODEL_B = "gemini-3.1-flash-lite"  # 모델 간 비교용
LOCAL_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"

random.seed(SEED); np.random.seed(SEED)


# ---------- Gemini + 캐시 ----------
_client = None
def _gem():
    global _client
    with _lock:   # 스레드가 동시에 클라이언트를 만들면 하나가 닫혀 버린다
        if _client is None:
            from google import genai
            _client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        return _client


# 무료 티어는 모델당 분당 15회. 모델별로 호출 간격을 강제하고, 429가 나오면 메시지의 limit·retry 시간을 따른다.
_rpm = {}       # model -> 현재 허용 RPM
_next = {}      # model -> 다음 호출 가능 시각
def _throttle(model):
    with _lock:
        rpm = _rpm.get(model, 12)
        t = max(time.time(), _next.get(model, 0))
        _next[model] = t + 60.0 / rpm
    wait = t - time.time()
    if wait > 0:
        time.sleep(wait)


def _on_429(model, msg):
    import re
    m = re.search(r"limit: (\d+)", msg)
    if m:
        _rpm[model] = max(2, int(int(m.group(1)) * 0.8))
    if "PerDay" in msg or "per day" in msg.lower():
        raise RuntimeError(f"일일 한도 초과({model}, limit={m.group(1) if m else '?'}회/일). 캐시는 유지되니 초기화(한국 시간 오후 5시경) 뒤 다시 실행하면 이어서 진행된다.")
    r = re.search(r"retry in ([\d.]+)s", msg)
    wait = float(r.group(1)) + 2 if r else 20
    with _lock:
        _next[model] = max(_next.get(model, 0), time.time() + wait)
    return wait


def _key(model, system, prompt, temperature, tag):
    s = json.dumps([model, system, prompt, temperature, tag], ensure_ascii=False)
    return hashlib.sha256(s.encode()).hexdigest()


def gemini(prompt, system=None, temperature=0.0, tag="", model=None, max_tokens=512, retries=6):   # 503 재시도도 일일 한도(500회)를 소모하므로 적게, 길게 쉬면서 시도한다
    """tag: 같은 프롬프트를 반복 샘플링할 때 구분용(예: 'rep3'). 캐시 키에 포함된다."""
    model = model or GEMINI_MODEL
    f = CACHE / f"{model.replace('/', '_')}.jsonl"
    k = _key(model, system, prompt, temperature, tag)
    with _lock:
        if not hasattr(gemini, "_mem"):
            gemini._mem = {}
        if f not in gemini._mem:
            d = {}
            if f.exists():
                for line in f.read_text(encoding="utf-8").splitlines():
                    try:
                        r = json.loads(line); d[r["k"]] = r["out"]
                    except Exception:
                        pass
            gemini._mem[f] = d
        mem = gemini._mem[f]
    if k in mem:
        return mem[k]
    if os.environ.get("GEMINI_COUNT_MISS"):   # 호출 없이 캐시에 없는 요청 수만 센다 (남은 호출량 계산용)
        with _lock:
            MISSES.setdefault(model, set()).add(k)
        return ""
    if os.environ.get("GEMINI_CACHE_ONLY"):   # 재현 검증용: 캐시에 없으면 오류
        raise RuntimeError("캐시에 없는 Gemini 요청 (GEMINI_CACHE_ONLY)")
    from google.genai import types
    cfg = types.GenerateContentConfig(
        system_instruction=system, temperature=temperature, max_output_tokens=max_tokens,
        thinking_config=types.ThinkingConfig(thinking_level="minimal"))
    out = None
    for i in range(retries + 6):
        _throttle(model)
        try:
            r = _gem().models.generate_content(model=model, contents=prompt, config=cfg)
            out = (r.text or "").strip()
            break
        except Exception as e:  # 429는 안내된 시간만큼, 5xx는 지수 백오프
            s = str(e)
            if any(c in s[:20] for c in ("404", "400", "403")):
                raise
            if "429" in s[:20]:
                wait = _on_429(model, s)
            else:
                wait = min(180, 20 * 2 ** i)
                if i >= retries: raise
            print(f"[retry {i+1}] {model} {s[:40].replace(chr(10), ' ')} → {wait:.0f}s", flush=True)
            time.sleep(wait if "429" not in s[:20] else 1)   # 429 대기는 _throttle이 처리
    if out is None:
        raise RuntimeError("Gemini 호출 실패")
    with _lock:
        mem[k] = out
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"k": k, "out": out}, ensure_ascii=False) + "\n")
    return out


def gemini_many(jobs, workers=8, **kw):
    """jobs: [dict(prompt=..., system=..., temperature=..., tag=...)] → 같은 순서의 출력 리스트."""
    from concurrent.futures import ThreadPoolExecutor
    def run(j):
        return gemini(**{**kw, **j})
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(run, jobs))


# ---------- 로컬 Qwen ----------
_loc = {}
def local_lm():
    if not _loc:
        import torch
        torch.set_num_threads(int(os.environ.get("QWEN_THREADS", 4)))   # 같은 PC의 다른 작업과 CPU를 나눠 쓴다
        from transformers import AutoTokenizer, AutoModelForCausalLM
        tok = AutoTokenizer.from_pretrained(LOCAL_MODEL)
        m = AutoModelForCausalLM.from_pretrained(LOCAL_MODEL, torch_dtype=torch.float32)
        m.eval()
        _loc.update(tok=tok, model=m)
    return _loc["tok"], _loc["model"]


def local_choice_logits(chat, candidates):
    """chat 뒤 다음 토큰에서 candidates 각 단어의 원시 로짓. 온도는 호출 쪽에서 z/T로 적용한다."""
    import torch
    qf = CACHE / "qwen_logits.jsonl"            # 로컬 모델 결과도 디스크에 캐시한다 (같은 입력은 다시 계산하지 않음)
    k = hashlib.sha256(json.dumps([LOCAL_MODEL, chat, candidates], ensure_ascii=False).encode()).hexdigest()
    with _lock:
        if not hasattr(local_choice_logits, "_mem"):
            d = {}
            if qf.exists():
                for line in qf.read_text(encoding="utf-8").splitlines():
                    try:
                        r = json.loads(line); d[r["k"]] = r["z"]
                    except Exception:
                        pass
            local_choice_logits._mem = d
        mem = local_choice_logits._mem
    if k in mem:
        return np.array(mem[k], dtype=float)
    if os.environ.get("SKIP_LOCAL"):   # 호출 수 집계 전용: 캐시에 없으면 계산하지 않고 0을 돌려준다
        return np.zeros(len(candidates))
    tok, m = local_lm()
    text = tok.apply_chat_template(chat, tokenize=False, add_generation_prompt=True)
    ids = tok(text, return_tensors="pt")
    with torch.no_grad():
        logits = m(**ids).logits[0, -1]
    cand_ids = [tok.encode(c, add_special_tokens=False)[0] for c in candidates]
    z = logits[cand_ids].numpy().astype(float)
    with _lock:
        mem[k] = z.tolist()
        with open(qf, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"k": k, "z": z.tolist()}) + "\n")
    return z


def softmax_T(z, T=1.0):
    z = np.asarray(z, dtype=float) / T
    z = z - z.max()
    e = np.exp(z)
    return e / e.sum()


# ---------- 통계 ----------
def boot_ci(x, n=2000, seed=SEED, alpha=0.05):
    x = np.asarray(x, dtype=float)
    rng = np.random.RandomState(seed)
    m = [rng.choice(x, len(x)).mean() for _ in range(n)]
    return float(x.mean()), float(np.percentile(m, 100 * alpha / 2)), float(np.percentile(m, 100 * (1 - alpha / 2)))


def mcnemar_p(a, b):
    """a,b: 같은 항목에 대한 0/1(성공) 배열. 정확 이항 검정."""
    from scipy.stats import binomtest
    a, b = np.asarray(a), np.asarray(b)
    n01 = int(((a == 0) & (b == 1)).sum()); n10 = int(((a == 1) & (b == 0)).sum())
    if n01 + n10 == 0:
        return 1.0
    return float(binomtest(n01, n01 + n10, 0.5).pvalue)


def first_label(text, labels, default=None):
    """출력에서 가장 먼저 등장하는 라벨을 반환 (대소문자 무시)."""
    t = text.upper(); best, pos = default, 10**9
    for l in labels:
        i = t.find(l.upper())
        if i != -1 and i < pos:
            best, pos = l, i
    return best


def fleiss_kappa(M):
    """M: (items × categories) 각 칸은 해당 범주를 고른 평가 횟수 (평가자 수는 항목마다 같아야 함)."""
    M = np.asarray(M, dtype=float)
    N, k = M.shape; n = M[0].sum()
    p = M.sum(0) / (N * n)
    P = ((M ** 2).sum(1) - n) / (n * (n - 1))
    Pe = (p ** 2).sum()
    return float((P.mean() - Pe) / (1 - Pe)) if Pe < 1 else 1.0


def setup_plot():
    import matplotlib.pyplot as plt
    plt.rcParams["font.family"] = "Malgun Gothic"
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["figure.dpi"] = 110
    return plt


def fmt_ci(x):
    m, lo, hi = boot_ci(x)
    return f"{m:.3f} [{lo:.3f}, {hi:.3f}]"
