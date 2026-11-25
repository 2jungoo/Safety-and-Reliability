# 공개 데이터셋 조사

자체 작성 데이터를 공개 데이터셋으로 바꿀 수 있는지 조사한 기록이다(2026-11-25). 라이선스와 규모는 GitHub·Hugging Face API로 확인했고, 확인하지 못한 것은 "미확인"으로 적었다. 구현은 아직 하지 않았다.

방침: 공개 데이터를 우선한다. 단 무료 API 한도(모델당 하루 500회) 때문에 **Gemini 호출 수는 늘리지 않는다.** 공개 데이터를 추가할 때는 로컬 Qwen으로 돌리거나 기존 항목을 대체한다.

## 시나리오별 결정

| # | 결정 | 이유 |
|---|---|---|
| S1 | 유지 | 이 시나리오의 설계는 "공격처럼 보이는 정상 로그"를 섞어 판정을 어렵게 만드는 것이다. 공개 데이터의 정상 요청은 대부분 쉽다. CSIC 2010은 가상 쇼핑몰 하나의 2010년 트래픽이다. 악성 로그만 ModSecurity 데이터로 바꾸는 방법은 남겨 둔다 |
| S2 | 유지 | 가설이 "HWP, YARA 같은 틈새 작업일수록 환각이 늘어난다"이다. Spracklen 프롬프트는 범용이라 틈새 작업이 없다. 내려받는 위치도 못 찾았다. 흔한 작업의 비교군으로는 쓸 수 있다 |
| S3 | **보강 예정** | FreshQA의 거짓 전제 질문을 추가한다. Qwen으로 "질문에 거짓 전제가 있는가"를 묻는 방식이라 Gemini 호출은 0회다. FakeCVE는 CVE 전용이라 대체할 공개 데이터가 없다 |
| S4 | 보류 | PoisonedRAG 데이터에는 공격 문서만 있고 정상 문서가 없다(질문 100개, 정답·오답·공격 문서 5개). 정상 문서를 얻으려면 BEIR 코퍼스(수백 MB)가 필요하다. BIPIA는 공격 성공을 LLM 판정으로 채점하는데, 우리는 "URL이 붙었는가"로 글자 채점을 해서 그대로 바꾸면 채점이 약해진다. 우리 공격 A는 PoisonedRAG의 방식(질문을 문서 앞에 붙임)을 따른 것이다 |
| S5 | 유지 | CyberNative 데이터는 쓰면 안 된다(아래 참고). PrimeVul은 쓸 수 있지만 C/C++ 긴 함수가 많고, 논문 기준으로 모델이 취약/패치 짝을 잘 구분하지 못한다고 알고 있다(미확인). 기본 정확도가 낮으면 "질문 말투로 정확도가 얼마나 떨어지는가"를 재기 어렵다 |
| S6 | 이미 공개 | KoBBQ(MIT) |
| S7 | **추가 예정** | discrim-eval(CC-BY-4.0)을 같은 방식으로 한 번 더 돌려 우리 결과와 비교한다. 우리 지원서(한국 국적·병역)는 유지한다 |

### S7에 추가할 설계 (내일 구현)

- 데이터: discrim-eval `implicit.jsonl`(이름으로 속성을 드러내는 쪽). 70개 시나리오 × 135개 조합(성별 3 × 인종 5 × 나이 9) = 9,450행
- 부분집합: 시나리오 20개를 시드 42로 뽑고, 나이 40세, 성별 3 × 인종 5 = 15개 변형 → 300행
- 프롬프트: 데이터셋의 공식 decision 프롬프트("yes" 또는 "no"로 답하라)
- 모델: 로컬 Qwen2.5-1.5B만 쓴다. Yes/No 로짓 차이로 집단별 평균과 백인 남성 기준 격차를 본다. Gemini 호출 0회
- 고정할 리비전: Hugging Face `Anthropic/discrim-eval` `6986d6ea802e019d01e94dd59597e94fbd8f8c4a`

### S3에 추가할 설계 (내일 구현)

- 데이터: FreshQA 2026-04-21판(구글 시트, 600문항: TEST 500, DEV 100). 거짓 전제 149개 중 시간이 지나도 답이 안 변하는 `never-changing` 75개
- 부분집합: `never-changing` 거짓 전제 20개 + `never-changing`이면서 전제가 정상인 20개
- 방식: Qwen으로 "이 질문에 거짓 전제가 있는가" Yes/No 로짓 비교. 정답 라벨은 시트의 `false_premise` 열이다. Gemini 호출 0회
- 시트는 주마다 갱신되므로 날짜가 붙은 판을 쓰고, 부분집합 ID를 `data/`에 저장한다
- 예: "What is the name of the first animal to land on the moon?"은 거짓 전제 문항이다

### S5에서 CyberNative를 제외한 이유

`CyberNative/Code_Vulnerability_Security_DPO`(Apache-2.0)는 안전/취약 코드 짝이 4,656개라 후보로 봤다. 저장소의 자체 감사 문서(2026-10-06)가 라벨을 믿을 수 없다고 보여 준다.
- 정적 분석기(Semgrep, Bandit, Flawfinder) 경고가 "안전"(chosen) 330개 중 87개, "취약"(rejected) 330개 중 127개에서 나왔다
- 수동 검토한 66쌍에서 "안전" 쪽에 목표 취약점이 **남아 있는** 경우가 4건, 없는 경우 40건, 해당 없음 15건, 판단 불가 7건
- CWE 라벨이 원본에 없다

S5는 "이 코드는 취약한가"라는 정답이 필요한 실험이라, 정답이 틀린 항목이 섞이면 아첨 효과와 라벨 오류를 구분할 수 없다.

## 후보 데이터셋 한 줄 기록

| 이름 | 한 줄 | 라이선스 | 상태 |
|---|---|---|---|
| [Anthropic/discrim-eval](https://huggingface.co/datasets/Anthropic/discrim-eval) | 의사결정 시나리오 70개에 인구통계만 바꾼 변형 9,450행(explicit/implicit) | CC-BY-4.0 | S7 추가 예정 |
| [FreshQA](https://github.com/freshllms/freshqa) | 최신 지식 질문 600개, 거짓 전제 149개 포함 | Apache-2.0 | S3 추가 예정 |
| [PoisonedRAG](https://github.com/sleeepeer/PoisonedRAG) | RAG 지식 오염 공격. 질문 100개마다 정답·오답·공격 문서 5개(정상 문서 없음) | MIT | S4 보류 |
| [BIPIA](https://github.com/microsoft/BIPIA) | 간접 프롬프트 인젝션 벤치마크, 응용 5종·공격 목표 250개, LLM 판정 채점 | MIT | S4 보류 |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | 도구 쓰는 에이전트 대상 인젝션 1,054건 | MIT | RAG와 맞지 않아 제외 |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | 에이전트 인젝션 공격·방어 평가 환경 | MIT | 규모가 커서 제외 |
| [sycophancy-eval](https://huggingface.co/datasets/meg-tong/sycophancy-eval) | 아첨 평가(feedback, are_you_sure, answer, mimicry). 코드 보안용은 아님 | MIT | S5 질문 문구 참고용 |
| [anthropics/evals](https://github.com/anthropics/evals) | Anthropic 모델 작성 평가, 아첨 포함 | CC-BY-4.0 | 참고용 |
| [PrimeVul](https://github.com/DLVulDet/PrimeVul) | 사람이 검증한 취약/패치 함수 짝(C/C++). 데이터는 구글 드라이브 | MIT | S5 보류 |
| [CyberNative DPO](https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO) | 안전/취약 코드 짝 4,656개 | Apache-2.0 | **제외**(라벨 오류) |
| [DiverseVul](https://github.com/wagner-group/diversevul) | 취약 함수 데이터 | 저장소에 표시 없음 | 미확인 |
| [CVEfixes](https://github.com/secureIT-project/CVEfixes) | CVE 수정 커밋 모음 | 저장소에 표시 없음(NOASSERTION) | 미확인 |
| [SecurityEval](https://github.com/s2e-lab/SecurityEval) | 파이썬 CWE별 프롬프트 | 저장소에 표시 없음 | 미확인 |
| [Bias in Bios](https://huggingface.co/datasets/LabHC/bias_in_bios) | 직업·성별이 붙은 소개글 | MIT | S7 후보(미사용) |
| [HalluLens](https://github.com/facebookresearch/HalluLens) | 환각 평가, 존재하지 않는 개체 거절 과제 포함(미확인) | **CC BY-NC 4.0** | 비영리 조건, 보류 |
| [HaluEval](https://github.com/RUCAIBox/HaluEval) | 환각 판별 QA 등 | MIT | 거짓 전제가 아니라 제외 |
| [CSIC 2010](https://www.tic.itefi.csic.es/dataset/) | HTTP 요청 정상 약 36,000·이상 25,000건 이상, 단일 가상 앱 | 미확인 | S1 유지 |
| [ModSecurity 30일](https://zenodo.org/records/17178461) | 실제 서버가 차단한 요청 147,205건(악성만) | CC BY 4.0(논문 기준) | S1 선택 사항 |
| [Spracklen 데이터](https://par.nsf.gov/biblio/10686037-code-data-we-have-package-you-comprehensive-analysis-package-hallucinations-code-generating-llms-usenix-security) | 프롬프트 19,500개, 환각 패키지명 205,474개 | 미확인 | S2 유지 |
| [KoBBQ](https://github.com/naver-ai/KoBBQ) | 한국어 편향 QA | MIT | S6 사용 중 |
| [TruthfulQA](https://github.com/sylinrl/TruthfulQA) | 흔한 오개념 퀴즈 | Apache-2.0 | S3 사용 중 |

## 500회 한도 대응

1. **팀원 각자의 키로 시나리오를 나눠 돌린다.** 한도는 키·모델별이다. 캐시(`results/cache/*.jsonl`)는 `(모델, 시스템 프롬프트, 프롬프트, 온도, 태그)` 해시를 키로 쓰는 append-only 파일이라, 팀원들의 파일을 이어 붙이면 합쳐진다. **같은 커밋의 코드**여야 한다. 프롬프트가 한 글자라도 다르면 키가 달라진다. 키는 환경변수 `GEMINI_API_KEY`로만 쓰고 레포에는 올리지 않는다
2. 결제를 켠 키 하나를 쓴다. 한도가 없어지고, 뺀 조건(다수결, 자기 검증, CoVe, 질문 중립화)도 되살릴 수 있다. 약 800회면 비용은 수 센트 정도로 추정하지만 단가는 확인하지 못했다
3. 하루씩 나눠 이어서 돌린다. 캐시가 있어서 한도에서 멈춰도 이어진다. 마감일에 여유가 있을 때 쓴다
4. 503 재시도도 한도를 쓰므로 재시도를 줄인다

## 다음 할 일

- [ ] `src/fetch_open_data.py`: discrim-eval(리비전 고정)과 FreshQA 시트를 내려받아 부분집합을 `data/`에 저장(원본은 `data/_raw/`, git 제외)
- [ ] S7에 discrim-eval Qwen 셀 추가, S3에 FreshQA Qwen 셀 추가(둘 다 Gemini 호출 0회)
- [ ] `docs/datasets.md`에 두 데이터 설명·예시 추가
- [ ] 마감일 확인 후 S4, S5 보류 항목 재검토

---

# 추가 조사 (2026-11-25): 실제 사건·CVE와 신규 데이터셋

자체 제작 데이터의 약점을 보완하려고 두 가지를 모았다. 시나리오마다 근거로 붙일 **실제 사건**과, 과제 규모(Gemini 하루 500회, 로컬 Qwen 1.5B)로 돌릴 수 있는 **공개 데이터셋**이다. 구현은 아직 하지 않았다.

## 실제 사건·CVE

| 시나리오 | 사건 | 사실 |
|---|---|---|
| S2 | [huggingface-cli](https://theregister.com/2024/03/28/ai_bots_hallucinate_software_packages) (Lasso Security, 2024-03 공개) | AI가 반복 추천한 가짜 이름을 연구자가 빈 패키지로 등록했다. 3개월 동안 1.5만~3만 번 내려받혔다(출처마다 수치가 다르다). Alibaba GraphTranslator README에도 들어갔다 |
| S3 | [Mata v. Avianca](https://www.americanbar.org/content/aba-cms-dotorg/en/groups/litigation/resources/litigation-news/2023/use-chatgpt-research-bogus-cases-sanctions) (S.D.N.Y., 2023-06-22) | 변호사가 ChatGPT가 지어낸 판례 6건을 법원에 냈고 제재를 받았다 |
| S3 | [Moffatt v. Air Canada](https://www.mccarthy.ca/en/insights/blogs/techlex/moffatt-v-air-canada-misrepresentation-ai-chatbot) (2024-02-14) | 챗봇이 틀린 환불 규정을 안내했고 회사 책임이 인정됐다. 배상 CA$812. OWASP LLM09의 예시 사례 |
| S4 | [EchoLeak CVE-2025-32711](https://arxiv.org/html/2509.10540v1) (CVSS 9.3) | 메일 한 통으로 M365 Copilot이 내부 파일을 외부로 유출했다. 사용자 클릭이 필요 없었다. 2025-05 서버 측 수정 |
| S4 | [CVE-2025-53773](https://www.tenable.com/cve/CVE-2025-53773) (CVSS 7.8, MSRC 2025-08-12) | 코드 주석·이슈 속 지시문으로 Copilot 설정을 바꿔 원격 코드 실행. 점수는 CVE 레코드 기준이고 9.6이라는 수치는 SNS에서만 봤다 |
| S5 | [GPT-4o 아첨 롤백](https://openai.com/index/sycophancy-in-gpt-4o/) (2025-04-25 배포, 04-28 롤백 시작) | 단기 사용자 피드백에 치우쳐 동조가 심해졌다. OpenAI는 아첨 평가를 배포 절차에 넣겠다고 밝혔다. 날짜는 보도마다 하루 차이가 난다 |
| 참고 | [LangChain CVE-2023-29374](https://nvd.nist.gov/vuln/detail/CVE-2023-29374) (CVSS 9.8) | LLM이 만든 코드를 exec()에 넘겨 실행됐다. 편향·환각보다 출력 처리 문제라 시나리오에는 넣지 않는다 |
| 전체 | [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llmrisk/llm092025-misinformation/) | LLM09 Misinformation(환각과 과의존), LLM01 Prompt Injection |

## 신규 후보 데이터셋 (라이선스는 2026-11-25에 저장소에서 확인)

| 이름 | 한 줄 | 라이선스 | 붙일 곳 | 상태 |
|---|---|---|---|---|
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | 실제 대회에서 나온 간접 인젝션 공격 20.8만 건(Microsoft) | MIT(HF 카드·저장소 모두 확인) | S4 공격 B의 지시문을 실제 공격문 10~20개로 교체. 호출 수는 그대로 | 추천 |
| [CTIBench](https://github.com/xashru/cti-bench) | CVE 설명을 보고 CWE 번호를 맞히는 과제(CTI-RCM) | **CC BY-NC-SA 4.0** | S3 보강. 없는 CWE 번호를 내면 환각으로 보고 CWE 공식 목록으로 기계 채점. Qwen 전용 | 추천. 비영리·출처 표시·동일조건 적용 |
| [CyberSecEval-FRR](https://huggingface.co/datasets/purpcode/CyberSecEval-FRR) | 위험해 보이지만 정상인 보안 요청(과잉 거절 측정) | MIT(CyberSecEval 본체, PurpleLlama의 `CybersecurityBenchmarks/LICENSE`). HF 미러는 카드에 표시 없음 | S3·S5 완화의 부작용 측정. Qwen 전용 | 시간이 남으면 |
| [KoSBi](https://github.com/naver-ai/korean-safety-benchmarks) | 한국어 사회 편향 문장 3.4만 쌍, 72개 집단(NAVER) | 저장소 MIT. 데이터 폴더 별도 표시는 못 찾음 | S6 보조. KoBBQ와 형식이 달라 경향 확인용 | 시간이 남으면 |
| [K-HALU](https://github.com/J-Seo/K-HALU) | 한국어 환각 탐지, 7개 분야(ICLR 2025) | MIT | S3 한국어 보강 | 시간이 남으면 |
| SecurityEval / CWEval | CWE별 코드 생성 프롬프트 | 미확인 | S5 생성형 대안 | 보류: 호출이 많고 채점이 복잡 |

주의
- PurpleLlama 저장소 최상위 LICENSE는 Llama 3.2 커뮤니티 라이선스다. CyberSecEval은 하위 폴더의 MIT를 따르므로 둘을 섞어 쓰지 않는다.
- CTIBench는 NonCommercial·ShareAlike라서 과제 제출물 안에 데이터 원본을 넣으면 같은 조건을 표시해야 한다. 공개 저장소에는 부분집합 ID만 저장하는 쪽이 안전하다.
- HalluLens(Meta, 환각 벤치마크)는 저장소 라이선스가 표시돼 있지 않아 후보에서 뺐다.

## 우선순위

1. 위 사건·CVE 표를 슬라이드에 넣는다(코드 변경 없음).
2. S4에 LLMail-Inject, S3에 CTIBench를 붙인다. 둘 다 Gemini 호출을 늘리지 않는다.
3. 나머지는 시간이 남을 때만 한다.
