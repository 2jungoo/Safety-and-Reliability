"""발표자료 틀. 결과 그림 자리는 회색 더미 상자이고, results/figures/sN.png가 생기면 그 그림으로 자동 교체된다.
실행: python slides/build_slides.py  ->  slides/build/deck.pptx   (build/는 .gitignore)
더미 상자에는 가짜 수치를 넣지 않는다. 결과가 나오면 "(결과 후 작성)" 문구와 표만 채우면 된다.
"""
import os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.dml import MSO_LINE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx_helpers import (new_prs, add_slide, table, textbox, bullets, callout, notes, image,
                          GRAY, LIGHT, BLUE, DARK)
from incidents_slide import add_incident_slide

FIG = os.path.join(ROOT, "results", "figures")
TBD = "(결과 후 작성)"

# 시나리오별 그림 자리. panels는 scenarios/sN_*.py의 subplot 구성과 같다.
SCEN = [
    dict(id="S1", title="S1 비일관성 — 같은 로그를 물어도 판정이 바뀐다", fig="s1.png", kind="환각·신뢰성",
         mit="T=0 고정, 구조화 출력(근거 후 판정)",
         panels=["판정이 뒤집힌 로그 비율 (낮을수록 좋음)", "Fleiss κ (높을수록 일관)", "정확도"],
         csv=["s1_summary.csv", "s1_qwen_temperature.csv"]),
    dict(id="S2", title="S2 패키지 환각 — 없는 패키지를 추천한다 (slopsquatting)", fig="s2.png", kind="환각",
         mit="정직 프롬프트, 레지스트리 게이트(PyPI에 없으면 버림)",
         panels=["환각 패키지 비율", "작업 유형별 환각률 (흔한 작업 vs 틈새 작업)", "응답당 추천 수 (유용성 비용)"],
         csv=["s2_summary.csv", "s2_packages_base.csv"]),
    dict(id="S3", title="S3 거짓 전제 환각 — 없는 CVE·표준을 지어낸다", fig="s3.png", kind="환각",
         mit="정직 프롬프트, NVD 검색 증강(CVE만)",
         panels=["CVE 31개: 환각률 vs 과잉 거절률", "TruthfulQA MC100 정확도 (Qwen 1.5B)"],
         csv=["s3_summary_all40.csv", "s3_summary_cve31.csv", "s3_truthfulqa.csv"]),
    dict(id="S4", title="S4 RAG 오염과 간접 프롬프트 인젝션", fig="s4.png", kind="환각+보안",
         mit="D1 spotlighting, D2 출처 서명 필터, D3 충돌 시 단정 금지",
         panels=["공격 성공률 (공격 A·B·C × 방어)", "공격 없을 때 정상 질문 결과 (방어의 부작용)"],
         csv=["s4_summary.csv", "s4_items.csv"]),
    dict(id="S5", title="S5 아첨 — \"안전하죠?\"라고 물으면 취약한 코드도 안전하다고 한다", fig="s5.png", kind="편향(아첨)",
         mit="반아첨 시스템 프롬프트, 공격자 시점 분석",
         panels=["취약 코드 탐지율 (높을수록 좋음)", "안전 코드 오탐률 (낮을수록 좋음)"],
         csv=["s5_summary.csv", "s5_qwen.csv"]),
    dict(id="S6", title="S6 사회적 편향 — 한국어 고정관념과 온도에 의한 증폭 (KoBBQ)", fig="s6.png", kind="편향(사회)",
         mit="편향 인식 프롬프트, 근거 인용 CoT",
         panels=["Gemini: 완화에 따른 모호·명확 정확도", "Gemini: 모호 문맥 편향점수 (0이 이상적)", "Qwen: 온도와 편향 답 비중"],
         csv=["s6_gemini.csv", "s6_qwen_temperature.csv", "s6_model_size.csv"]),
    dict(id="S7", title="S7 할당 편향 — 이름·성별·출신만 바꾸면 채용 결과가 달라지는가", fig="s7.png", kind="편향(할당)",
         mit="공정성 지시, 이름·성별 블라인딩, 완전 블라인딩",
         panels=["Qwen: 평균 로짓 마진 격차 (KM − 비교집단)", "Gemini: 반사실 뒤집힘률 (통제군 잡음선 포함)"],
         csv=["s7_gemini.csv", "s7_qwen.csv"]),
]


def placeholder(slide, x, y, w, h, lines):
    """회색 점선 더미 상자."""
    box = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    box.fill.solid(); box.fill.fore_color.rgb = RGBColor(0xF2, 0xF2, 0xF2)
    box.line.color.rgb = RGBColor(0xA0, 0xA0, 0xA0); box.line.width = Pt(1.5); box.line.dash_style = MSO_LINE.DASH
    tf = box.text_frame; tf.word_wrap = True; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for i, (txt, size, bold) in enumerate(lines):
        par = tf.paragraphs[0] if i == 0 else tf.add_paragraph(); par.alignment = PP_ALIGN.CENTER
        r = par.add_run(); r.text = txt; r.font.size = Pt(size); r.font.bold = bold
        r.font.name = "맑은 고딕"; r.font.color.rgb = GRAY
    return box


def scenario_slide(prs, sc, page):
    s = add_slide(prs, sc["title"], page)
    path = os.path.join(FIG, sc["fig"])
    X, Y, W, Hh = Inches(0.5), Inches(1.2), Inches(12.3), Inches(3.7)
    if os.path.exists(path):
        image(s, path, X, Y, h=Hh)
    else:
        placeholder(s, X, Y, W, Hh,
                    [("[더미] 결과 그림 자리", 24, True), (f"results/figures/{sc['fig']}", 16, False),
                     ("패널 " + str(len(sc["panels"])) + "개: " + " / ".join(sc["panels"]), 13, False)])
    bullets(s, [f"완화: {sc['mit']}", f"핵심 발견 1: {TBD}", f"핵심 발견 2: {TBD}",
                f"부작용·한계: {TBD}"], Inches(0.5), Inches(5.05), Inches(7.6), Inches(1.9), size=16)
    callout(s, f"한 줄 결론\n{TBD}", Inches(8.4), Inches(5.2), Inches(4.4), Inches(1.4), size=15, color=BLUE)
    notes(s, f"표 원본: results/{', results/'.join(sc['csv'])}. 수치는 CSV와 같아야 한다(verify.py V5에서 대조).")
    return s


def build():
    prs = new_prs(); page = 1

    s = add_slide(prs, "안전·신뢰 AI 구현 — 편향·환각 사례 분석", page); page += 1
    textbox(s, Inches(0.8), Inches(2.2), Inches(11.7), Inches(1.0), "보안 맥락의 환각 4개와 편향 3개를 구현하고, 완화 기법의 효과와 부작용을 측정했다", size=22)
    textbox(s, Inches(0.8), Inches(4.4), Inches(11.7), Inches(1.4), "한성대학교 융합보안 · 안전·신뢰 AI 구현 (석병진 교수)\n팀원1 · 팀원2 · 팀원3 · 팀원4 · 팀원5 · 팀원6 · 팀원7  (이름·역할은 회의 후 기입)", size=16, color=GRAY)

    s = add_slide(prs, "문제 정의: 환각과 편향이 보안 문제가 되는 순간", page); page += 1
    bullets(s, [f"환각: {TBD}", f"편향: {TBD}", f"왜 보안 맥락인가: {TBD}"], Inches(0.8), Inches(1.5), Inches(11.7), Inches(4), size=20)

    s = add_slide(prs, "시나리오 7개와 완화 기법", page); page += 1
    rows = [["#", "유형", "무엇을 보나", "완화 기법"]] + [[c["id"], c["kind"], re.sub(r"^S\d\s+", "", c["title"].split("— ", 1)[-1]), c["mit"]] for c in SCEN]
    table(s, rows, Inches(0.5), Inches(1.3), Inches(12.3), col_w=[0.6, 1.6, 5.6, 5.0], size=13, row_h=0.6)

    add_incident_slide(prs, page); page += 1

    s = add_slide(prs, "데이터: 공개 벤치마크와 자체 제작", page); page += 1
    rows = [["구분", "이름", "시나리오", "정답을 어디서 얻나"],
            ["공개", "KoBBQ, TruthfulQA (추가 예정: discrim-eval, FreshQA)", "S6, S3, S7", "벤치마크 정답"],
            ["자체", "SecLog-40, VulnSyco-24, 한빛전자 코퍼스, 반사실 지원서", "S1, S5, S4, S7", "직접 라벨링 + 표본 검수(V3)"],
            ["자체", "PkgHallu-60, FakeCVE-40", "S2, S3", "PyPI·NVD API로 실존 확인"]]
    table(s, rows, Inches(0.5), Inches(1.4), Inches(12.3), col_w=[0.9, 6.0, 2.2, 3.2], size=14, row_h=0.7)
    bullets(s, [f"규모와 한계: {TBD}"], Inches(0.5), Inches(4.8), Inches(12.3), Inches(1), size=16)

    for sc in SCEN:
        scenario_slide(prs, sc, page); page += 1

    s = add_slide(prs, "완화 효과 종합 — 무엇이 얼마나 나아졌고 무엇을 잃었나", page); page += 1
    rows = [["#", "기본(완화 전)", "최선의 완화", "개선폭", "부작용"]] + [[c["id"], "—", "—", "—", "—"] for c in SCEN]
    table(s, rows, Inches(0.5), Inches(1.4), Inches(12.3), col_w=[0.8, 2.6, 3.6, 2.0, 3.3], size=14, row_h=0.55)
    textbox(s, Inches(0.5), Inches(6.2), Inches(12.3), Inches(0.5), f"표 수치는 결과 CSV에서 가져온다 {TBD}", size=13, color=GRAY)

    s = add_slide(prs, "한계", page); page += 1
    bullets(s, ["표본이 작다(24~60문항, S3는 1회) — 경향 확인용이다", "자체 제작 데이터가 많다 — 외부 API 정답과 표본 검수(V3)로 보완했다",
                "무료 API 한도로 일부 완화 기법을 뺐다(다수결, 자기 검증, CoVe, 질문 중립화)", "로컬 모델이 작다(Qwen 1.5B)", f"추가: {TBD}"],
            Inches(0.8), Inches(1.5), Inches(11.7), Inches(4.5), size=20)

    s = add_slide(prs, "결론", page); page += 1
    bullets(s, [f"결론 1: {TBD}", f"결론 2: {TBD}", f"결론 3: {TBD}", f"실무 시사점: {TBD}"], Inches(0.8), Inches(1.5), Inches(11.7), Inches(4.5), size=20)
    return prs


if __name__ == "__main__":
    out_dir = os.path.join(HERE, "build"); os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "deck.pptx")
    prs = build(); prs.save(out)
    print("저장:", out, "| 슬라이드", len(prs.slides._sldIdLst), "장")
