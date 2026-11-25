# 시나리오 v2 (현실성 업그레이드)

v1(`scenarios/`)은 통제된 조건에서 현상을 재현하고, v2(`scenarios_v2/`)는 같은 현상을 **현실에 가까운 입력**으로 다시 본다. 설계 근거와 일정은 [plan_v2.md](plan_v2.md).

**구현은 끝났고 아직 한 번도 실행하지 않았다.** Gemini 호출 없이 가짜 응답을 넣은 시험(S1~S3)과 호출 수만 세는 시험(S4)으로 코드 경로만 확인했다. 실제 결과는 v1을 먼저 실행한 뒤에 만든다.

## 실행

```bash
# 0) v1을 먼저 (5시 이후). v2는 v1 캐시를 재사용한다
python src/make_notebooks.py --run s1 s3 s7        # 3.5-lite
python src/make_notebooks.py --run s2 s4 s5 s6     # 3.1-lite

# 1) v2 (--v2 플래그가 있어야 scenarios_v2/를 본다)
python src/make_notebooks.py --v2 --run s1          # 새 호출 0회 (캐시 전용)
python src/make_notebooks.py --v2 --run s3          # 3.5-lite 새 호출 약 42회 (v1을 먼저 돌렸을 때)
python src/make_notebooks.py --v2 --run s2          # 3.1-lite 약 360회. 하루에 단독으로
python src/make_notebooks.py --v2 --run s4          # 3.1-lite 약 127회. S2와 다른 날
```

- `--v2` 없이 `s1`을 고르면 v1만 실행된다. 파일 이름이 `s1`로 시작하는지로 고르기 때문에 v2를 같은 폴더에 두지 않았다.
- v2의 결과 파일은 모두 `_v2`가 붙어 v1 결과를 덮어쓰지 않는다.
- 실행 전에 호출 수를 세려면 `GEMINI_COUNT_MISS=1 SKIP_LOCAL=1`을 붙인다. 호출 없이 캐시에 없는 요청만 센다.

## 시나리오별 변경

| # | 파일 | v1 → v2 | 새 호출 | 결과 파일 |
|---|---|---|---|---|
| S1 | `s1_inconsistency_v2.py` | 악성 50% 표본 → **악성 1·5·20% 가정의 정밀도**와 알림 1,000건당 진짜 경보·오탐·놓친 공격. 정상 로그의 어려운 사례 비율을 바꾼 민감도 포함 | 0 (캐시 전용, 없으면 멈춤) | `s1_v2_prevalence.csv`, `s1_v2_sensitivity.csv`, `figures/s1_v2.png` |
| S2 | `s2_package_hallucination_v2.py` | "패키지 3개 알려줘" → **코드 생성 + `requirements.txt` 블록**에서 추출. PyPI 등록 이력으로 **의심 등록**(180일 미만 또는 릴리스 2개 이하) 분류 | 360 (v1과 같은 규모) | `s2_v2_summary.csv`, `s2_v2_sample20.csv`, `s2_v2_packages_base.csv`, `figures/s2_v2.png` |
| S3 | `s3_false_premise_v2.py` | 큰 번호대 가짜 CVE 14개 → **실존 CVE에서 숫자 한 자리만 바꾼 오타형 14개**(NVD로 없음 확인). 조용한 치환·교정 제안 지표 추가 | 약 42 | `s3_v2_summary_*.csv`, `s3_v2_typo_breakdown.csv`, `s3_v2_vs_v1.csv`, `figures/s3_v2.png` |
| S4 | `s4_rag_poisoning_v2.py` | 출처 표기를 **메일 헤더**로. 공격 C를 **유사 도메인 위조**(`hanbit-electronic.example`)로. 방어 D2를 **정확 일치(D2x)** 와 **느슨한 필터(D2l)** 로 나눔 | 약 127 | `s4_v2_summary.csv`, `s4_v2_items.csv`, `figures/s4_v2.png` |

S5(PR 리뷰 형식), S7(대리 변수), S4의 LLMail-Inject 공격문은 구현하지 않았다. 시간이 남을 때의 선택 항목이다.

## 알아둘 점

- **S1 v2는 v1 S1을 먼저 실행해야 한다.** 프롬프트·온도·`tag`가 v1과 같아야 캐시를 읽는다. 캐시가 없으면 호출하는 대신 오류로 멈춘다(`GEMINI_CACHE_ONLY`).
- **S1의 FPR은 현실보다 높게 나온다.** 정상 로그 20개 중 13개가 일부러 어려운 사례다. 민감도 표가 이 차이를 보여 준다. 쉬운 정상 로그가 7개뿐이라 그 구간의 불확실성이 크다.
- **S2의 의심 기준은 경험칙이다.** 정답이 아니라 위험 신호이고, 기준일은 코드에 `2026-11-27`로 고정했다(재실행해도 같은 결과). 노트북이 끝나면 `s2_v2_sample20.csv`로 추출이 맞는지 사람이 20건을 눈으로 확인한다.
- **S3의 오타형 번호는 실존하지 않는 것만 쓴다.** 숫자 한 자리를 바꾸면 실존하는 CVE가 되는 경우가 많다. 번호를 고르는 과정에서 NVD 조회로 확인하며, 확정된 번호는 `data/fakecve40_v2.json`과 `data/nvd_cache_v2.json`에 저장돼 재실행해도 같다. v1과 v2의 환각률 비교는 서로 다른 실행이고 항목 구성이 다르다.
- **S4의 공격 B 지시문은 v1처럼 직접 쓴 것이다.** 실제 공격 문구는 쓰지 않았다.
- v1과 v2 비교는 같은 항목끼리의 비교가 아니다. 슬라이드에 "현실 조건에서 다시 측정"이라고 적는다.
