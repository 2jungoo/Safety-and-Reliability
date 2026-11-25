# 결과 그림 자리 (더미 틀)

발표자료의 결과 그림 자리를 미리 정해 둔 명세다. `python slides/build_slides.py`를 실행하면 `slides/build/deck.pptx`가 만들어진다. `results/figures/sN.png`가 없으면 회색 점선 더미 상자("[더미] 결과 그림 자리")가 들어가고, 있으면 그 그림으로 자동 교체된다. 더미에는 가짜 수치를 넣지 않았다.

그림은 각 시나리오 노트북이 `results/figures/`에 저장한다. 패널 구성은 `scenarios/sN_*.py`의 `plt.subplots`와 같다.

## 시나리오별 그림 자리

| 슬라이드 | 그림 파일 | 패널 | 좋은 방향 | 표 원본 (`results/`) |
|---|---|---|---|---|
| S1 비일관성 | `figures/s1.png` | ① 판정이 뒤집힌 로그 비율 ② Fleiss κ ③ 정확도 | ① 낮을수록 ② 높을수록 ③ 높을수록 | `s1_summary.csv`, `s1_qwen_temperature.csv` |
| S2 패키지 환각 | `figures/s2.png` | ① 환각 패키지 비율 ② 작업 유형별 환각률(흔한 vs 틈새) ③ 응답당 추천 수 | ①② 낮을수록, ③ 유용성 비용 | `s2_summary.csv`, `s2_packages_base.csv` |
| S3 거짓 전제 | `figures/s3.png` | ① CVE 31개 환각률 vs 과잉 거절률 ② TruthfulQA MC100 정확도(Qwen) | ① 둘 다 낮을수록 ② 높을수록 | `s3_summary_all40.csv`, `s3_summary_cve31.csv`, `s3_truthfulqa.csv` |
| S4 RAG 오염 | `figures/s4.png` | ① 공격 성공률(공격 A·B·C × 방어) ② 공격 없을 때 정상 질문 결과 | ① 낮을수록 ② 정답이 높을수록(방어의 부작용 확인) | `s4_summary.csv`, `s4_items.csv` |
| S5 아첨 | `figures/s5.png` | ① 취약 코드 탐지율 ② 안전 코드 오탐률 | ① 높을수록 ② 낮을수록 | `s5_summary.csv`, `s5_qwen.csv` |
| S6 사회적 편향 | `figures/s6.png` | ① 완화별 모호·명확 정확도 ② 모호 문맥 편향점수 ③ Qwen 온도와 편향 답 비중 | ② 0이 이상적, ③ 온도가 낮을수록 커지는지 | `s6_gemini.csv`, `s6_qwen_temperature.csv`, `s6_model_size.csv` |
| S7 할당 편향 | `figures/s7.png` | ① Qwen 평균 로짓 마진 격차(KM−KF, KM−FM) ② Gemini 반사실 뒤집힘률(통제군 잡음선) | 0과 잡음선에 가까울수록 | `s7_gemini.csv`, `s7_qwen.csv` |

## 시나리오 외 슬라이드

| 슬라이드 | 내용 | 채울 것 |
|---|---|---|
| 표지 | 제목, 팀원1~7 | 팀원 이름·역할 |
| 문제 정의 | 환각, 편향, 왜 보안 맥락인가 | 문장 3줄 |
| 시나리오 7개와 완화 기법 | 표 (자동 생성) | 없음 |
| 사건·CVE | `slides/incidents_slide.py` | 없음 |
| 데이터 | 공개 벤치마크와 자체 제작 표 | 규모와 한계 한 줄 |
| 완화 효과 종합 | 시나리오별 기본·최선 완화·개선폭·부작용 표(현재 "—") | 결과 CSV에서 수치 |
| 한계 | 표본 크기, 자체 데이터, 한도, 모델 크기 | 추가 한계 |
| 결론 | 결론 3개, 실무 시사점 | 문장 |

## 결과가 나온 뒤 할 일

1. 실험 후 `results/figures/s1.png ~ s7.png`가 생기면 `python slides/build_slides.py`를 다시 실행한다. 그림 자리가 자동으로 교체된다.
2. 각 슬라이드의 "(결과 후 작성)" 줄과 종합표를 채운다. 수치는 위 표의 CSV와 같아야 한다(`verify.py` V5에서 대조).
3. PowerPoint로 PDF를 내보내 글자가 잘리거나 겹치는지 확인한다.
