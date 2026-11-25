"""실제 사건·CVE 표 슬라이드. build_slides.py가 생기면 add_incident_slide()를 가져다 쓴다.
단독 실행: python slides/incidents_slide.py  ->  slides/incidents.pptx
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pptx.util import Inches
from pptx_helpers import new_prs, add_slide, table, textbox, notes, GRAY

ROWS = [
    ["시나리오", "실제 사건", "무슨 일이 있었나", "출처"],
    ["S2 패키지 환각", "huggingface-cli\n(2024-03)", "AI가 반복 추천한 가짜 이름을 빈 패키지로 등록했더니 3개월간 1.5만~3만 번 설치됐다. Alibaba 프로젝트 README에도 들어갔다", "The Register"],
    ["S3 거짓 전제", "Mata v. Avianca\n(2023-06-22)", "변호사가 ChatGPT가 지어낸 판례 6건을 법원에 제출해 제재받았다", "ABA, 법원 명령문"],
    ["S3 거짓 전제", "Moffatt v. Air Canada\n(2024-02-14)", "챗봇이 틀린 환불 규정을 안내했고 회사 책임이 인정됐다. 배상 CA$812", "McCarthy Tétrault"],
    ["S4 RAG 인젝션", "EchoLeak\nCVE-2025-32711 (CVSS 9.3)", "메일 한 통으로 M365 Copilot이 내부 파일을 외부로 유출했다. 사용자 클릭 불필요", "arXiv 2509.10540"],
    ["S4 RAG 인젝션", "CVE-2025-53773\n(CVSS 7.8)", "코드 주석·이슈에 숨긴 지시문으로 Copilot 설정이 바뀌어 원격 코드 실행", "MSRC, Tenable"],
    ["S5 아첨", "GPT-4o 롤백\n(2025-04)", "업데이트 후 동조가 심해져 며칠 만에 되돌렸다. 단기 사용자 피드백에 치우친 탓", "OpenAI 블로그"],
]


def add_incident_slide(prs, page):
    s = add_slide(prs, "시나리오마다 실제로 일어난 사건이 있다", page)
    table(s, ROWS, Inches(0.5), Inches(1.3), Inches(12.3), col_w=[1.5, 2.4, 6.2, 2.0], size=13, row_h=0.7)
    textbox(s, Inches(0.5), Inches(6.55), Inches(12.3), Inches(0.5),
            "분류 기준: OWASP Top 10 for LLM 2025 — LLM09 Misinformation(환각·과의존), LLM01 Prompt Injection", size=13, color=GRAY)
    notes(s, "S6·S7(편향)은 사건 대신 벤치마크(KoBBQ, discrim-eval)로 근거를 잡는다. "
             "CVSS는 CVE 레코드 기준. GPT-4o 날짜는 보도마다 하루 차이가 난다(배포 04-25, 롤백 시작 04-28).")
    return s


if __name__ == "__main__":
    prs = new_prs()
    add_incident_slide(prs, 1)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.pptx")
    prs.save(out)
    print("저장:", out)
