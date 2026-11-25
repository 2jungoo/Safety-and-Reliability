"""scenarios/*.py (# %% 셀 형식) → notebooks/*.ipynb 변환, 선택적으로 실행.
사용: python make_notebooks.py [--run] [--v2] [s1 s2 ...]
--v2: scenarios_v2/ 의 현실성 업그레이드 시나리오를 대상으로 한다 (플래그가 없으면 v1인 scenarios/만 본다)."""
import sys, re, pathlib
import nbformat
from nbformat.v4 import new_notebook, new_code_cell, new_markdown_cell

ROOT = pathlib.Path(__file__).resolve().parents[1]
SC, NB = ROOT / ("scenarios_v2" if "--v2" in sys.argv else "scenarios"), ROOT / "notebooks"
NB.mkdir(exist_ok=True)


def convert(py):
    cells, cur, kind = [], [], None
    def flush():
        nonlocal cur, kind
        body = "\n".join(cur).strip("\n")
        if body:
            if kind == "md":
                body = "\n".join(re.sub(r"^# ?", "", l) for l in body.splitlines())
                cells.append(new_markdown_cell(body))
            else:
                cells.append(new_code_cell(body))
        cur = []
    for line in py.read_text(encoding="utf-8").splitlines():
        if line.startswith("# %%"):
            flush(); kind = "md" if "[markdown]" in line else "code"
        else:
            cur.append(line)
    flush()
    nb = new_notebook(cells=cells)
    nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
    return nb


def main():
    args = sys.argv[1:]
    run = "--run" in args
    names = [a for a in args if not a.startswith("--")]
    files = sorted(SC.glob("*.py"))
    if names:
        files = [f for f in files if any(f.name.startswith(n) for n in names)]
    for f in files:
        nb = convert(f)
        out = NB / (f.stem + ".ipynb")
        if run:
            from nbconvert.preprocessors import ExecutePreprocessor
            print("실행:", f.name, flush=True)
            try:
                ExecutePreprocessor(timeout=None, kernel_name="python3").preprocess(nb, {"metadata": {"path": str(NB)}})
            except Exception as e:   # 한 노트북이 실패해도 다음 노트북은 계속 실행한다 (진행된 곳까지의 출력은 .failed.ipynb에 남김)
                out = NB / (f.stem + ".failed.ipynb")
                print("실패:", f.name, "→", str(e).strip().splitlines()[-1][:300], flush=True)
        nbformat.write(nb, out)
        print("저장:", out.name, flush=True)


if __name__ == "__main__":
    main()
