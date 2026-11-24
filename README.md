# Safety-and-Reliability

안전·신뢰 AI 구현 기말 프로젝트(한성대 융합보안, 석병진 교수). LLM의 **편향**과 **환각**을 보안 맥락의 시나리오 7개로 재현하고, 벤치마크로 측정한 뒤 완화 기법의 효과와 부작용까지 비교한다.

![status](https://img.shields.io/badge/status-실험_전-orange)
![python](https://img.shields.io/badge/python-3.12-blue)
![models](https://img.shields.io/badge/models-Gemini_flash--lite_%7C_Qwen2.5--1.5B-green)

> **현재 상태 (2026-11-24)**: 시나리오 코드와 데이터는 준비됐고 **실험 결과는 아직 없다.** Gemini 무료 한도를 오늘 다 써서 11/25 오후 5시(한국 시간) 이후에 돌린다. 수치가 필요한 슬라이드는 그때 채운다.

## 시나리오

| # | 이름 | 유형 | 무엇을 보나 | 데이터 | 완화 기법 |
|---|---|---|---|---|---|
| S1 | 비일관성 | 신뢰성 | 같은 보안 로그를 여러 번 묻거나 표현만 바꿔 물으면 악성/정상 판정이 뒤집히는가 | SecLog-40 | T=0 고정, 구조화 출력 |
| S2 | 패키지 환각 | 환각 | 없는 PyPI 패키지를 추천하는가, 같은 가짜 이름이 반복되는가 | PkgHallu-60 | 정직 프롬프트, 레지스트리 게이트 |
| S3 | 거짓 전제 환각 | 환각 | 없는 CVE·NIST·RFC 번호를 물으면 내용을 지어내는가 | FakeCVE-40, TruthfulQA 100 | 정직 프롬프트, NVD 검색 증강 |
| S4 | RAG 오염 | 환각+보안 | 오염된 문서·간접 프롬프트 인젝션·출처 위조에 RAG 챗봇이 넘어가는가 | 한빛전자 규정 30조항 | spotlighting, 출처 서명 필터, 충돌 시 단정 금지 |
| S5 | 아첨 | 편향 | "안전하죠?"라고 물으면 취약한 코드도 안전하다고 하는가 | VulnSyco-24 | 반아첨 프롬프트, 공격자 시점 분석 |
| S6 | 사회적 편향 | 편향 | 모호한 문맥에서 고정관념으로 답하는가, 온도를 낮추면 증폭되는가 | KoBBQ 36 | 편향 인식 프롬프트, 근거 인용 CoT |
| S7 | 채용 반사실 | 편향 | 이름·성별·출신만 바꾸면 심사 결과가 달라지는가 | 반사실 지원서 12×3집단 | 공정성 지시, 이름·성별 블라인딩, 완전 블라인딩 |

처음 보면 [쉽게 보기](docs/scenarios_easy.md)부터 읽으면 된다. 시나리오별 실험 설계와 지표는 [docs/scenarios.md](docs/scenarios.md), 데이터 출처는 [docs/datasets.md](docs/datasets.md)에 있다.

## 폴더 구조

```
scenarios/   S1~S7 코드 (# %% 셀 형식 .py, 노트북으로 변환해 실행)
src/         common.py(Gemini 호출·캐시·Qwen·통계), make_notebooks.py, verify.py, dryrun.py
slides/      pptx_helpers.py (발표자료 생성 틀)
data/        데이터셋과 외부 조회 캐시(pypi_exists.json, nvd_cache.json)
docs/        시나리오·데이터셋 설명, 로드맵
```

## 실행

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=...        # Windows PowerShell: $env:GEMINI_API_KEY="..."

# 모델 두 개로 나눠 병렬 실행 (무료 한도가 모델별이라 시나리오마다 모델을 고정했다)
python src/make_notebooks.py --run s1 s3 s7      # gemini-3.5-flash-lite
python src/make_notebooks.py --run s2 s4 s5 s6   # gemini-3.1-flash-lite
```

- 노트북은 `notebooks/`, 결과는 `results/`에 생기고 둘 다 git에서 제외한다.
- Gemini 응답은 `results/cache/*.jsonl`에 쌓인다. 같은 요청은 다시 호출하지 않으므로 한도에 걸려도 이어서 실행하면 된다.
- 로컬 모델은 `Qwen/Qwen2.5-1.5B-Instruct`다. 처음 실행할 때 약 6GB를 내려받고 CPU 메모리를 크게 쓴다.
- `data/kobbq_sub36.json`, `data/hiring_base12.json`은 S6, S7을 실행하면 만들어진다.
- 무료 티어는 모델당 분당 15회, 하루 500회다. 3.x flash(비 lite) 계열은 하루 20회라 쓰지 않는다.

## 진행 상황

- [x] 시나리오 S1~S7 코드
- [x] 데이터셋 구성
- [x] 발표자료 틀 (`slides/pptx_helpers.py`)
- [ ] Gemini 실험 실행 (약 800회, 11/25 오후 5시 이후)
- [ ] 검증 5단계 `src/verify.py` (V1 작성됨, V2~V5 미작성)
- [ ] 발표자료 `build_slides.py`와 pptx 생성
- [ ] 구현물 zip 패키징

한도 때문에 **실험에서 뺀 조건**: S1 self-consistency 다수결, S2 자기 검증, S3 Chain-of-Verification, S5 질문 중립화. 함수는 코드에 남아 있고 결과에는 없다. 유료 키가 생기면 되살릴 수 있다.

## 팀

| 이름 | 역할 |
|---|---|
| 팀원1 | |
| 팀원2 | |
| 팀원3 | |
| 팀원4 | |
| 팀원5 | |
| 팀원6 | |
| 팀원7 | |

## 참고

- Sharma et al., *Towards Understanding Sycophancy in Language Models*, 2023
- Spracklen et al., *We Have a Package for You!*, USENIX Security 2025
- Jin et al., *KoBBQ: Korean Bias Benchmark for Question Answering*, TACL 2024 ([naver-ai/KoBBQ](https://github.com/naver-ai/KoBBQ))
- Lin et al., *TruthfulQA*, ACL 2022 ([sylinrl/TruthfulQA](https://github.com/sylinrl/TruthfulQA))
- Zou et al., *PoisonedRAG*, 2024
