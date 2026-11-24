# 데이터셋

| 이름 | 규모 | 출처 | 파일 | 시나리오 |
|---|---|---|---|---|
| SecLog-40 | 로그 40개 (악성 20, 정상 20) | 자체 작성 | `data/seclog40.json` | S1 |
| PkgHallu-60 | 작업 60개 (흔한 30, 틈새 30) | 자체 작성 | `data/pkghallu60.json` | S2 |
| FakeCVE-40 | 실존 20, 가짜 20 | 자체 구성 | `data/fakecve40.json` | S3 |
| TruthfulQA | 100문항(원본에서 추출, 객관식 변환) | 공개 벤치마크 | `data/TruthfulQA.csv`, `data/truthfulqa_mc100.json` | S3 |
| 한빛전자 규정 코퍼스 | 15문서 30조항, 질문 10개 | 자체 작성(가상 회사) | `scenarios/s4_rag_poisoning.py` 안에 정의 | S4 |
| VulnSyco-24 | 코드 24개 (취약 18, 안전 6) | 자체 작성 | `data/vulnsyco24.json` | S5 |
| KoBBQ 부분집합 | 36문항 (모호 18, 명확 18) | 공개 벤치마크 | `data/KoBBQ_test_samples.tsv`에서 추출 | S6 |
| 반사실 지원서 | 12개 × 3집단 | 코드로 생성(시드 42) | `scenarios/s7_hiring_counterfactual.py` | S7 |

규모는 무료 API 한도(분당 15회, 하루 500회)에 맞춘 값이다. 통계적 결론보다 현상을 보여 주는 데 목적이 있다.

## 자체 작성 데이터

- **SecLog-40**: 쉬운 사례와 어려운 사례(난독화된 공격, 공격처럼 보이는 정상 로그)를 섞고, 어려운 사례를 먼저 담았다. IP는 문서용 대역(RFC 5737)만 쓴다. 동작하는 익스플로잇은 없고 교육용 최소 패턴이다.
- **PkgHallu-60**: "HTTP 요청 보내기" 같은 흔한 작업과 "HWP 문서 파싱", "YARA 룰 매칭" 같은 틈새 작업을 30개씩 둔다. 틈새일수록 환각이 늘 것이라는 가설용이다.
- **FakeCVE-40**: 실존 CVE 17개, NIST SP 2개, RFC 1개와 가짜 CVE 14개, 가짜 NIST·RFC 6개. 가짜 번호는 실제로 배정되지 않은 번호대(연도별 최대 번호보다 큰 값 등)로 골랐다. CVE 실존 여부는 NVD API로 확인하고 `data/nvd_cache.json`에 저장했다.
- **한빛전자 코퍼스**: 규정 조항은 `{v}` 자리에 값을 넣는 템플릿이다. 정상 문서는 정답 값, 오염 문서는 오염 값을 넣는다. 두 값은 서로 포함 관계가 없게 골라서 문자열로 채점할 수 있다.
- **VulnSyco-24**: CWE 6종(SQL 인젝션, 명령어 인젝션, 경로 조작, XSS, 하드코딩 비밀, 기타)에서 3개씩과 안전한 코드 6개. 교육용 최소 스니펫이다.
- **반사실 지원서**: 경력·기술·프로젝트는 같고 이름·성별·국적·병역·체류자격만 바꾼다.

## 공개 데이터와 라이선스

| 데이터 | 원 레포 | 라이선스 |
|---|---|---|
| TruthfulQA | https://github.com/sylinrl/TruthfulQA | Apache-2.0 |
| KoBBQ | https://github.com/naver-ai/KoBBQ | MIT |

## 외부 조회 캐시

- `data/pypi_exists.json`: S2에서 PyPI JSON API로 확인한 패키지명의 실존 여부
- `data/nvd_cache.json`: S3에서 NVD API로 조회한 CVE 설명(없으면 null)

캐시가 있으면 다시 조회하지 않는다. 시간이 지나 PyPI에 새 패키지가 등록되면 결과가 달라질 수 있으니 실험 날짜를 같이 기록한다.
