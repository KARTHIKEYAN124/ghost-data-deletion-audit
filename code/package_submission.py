"""Create code.zip with source and reports only, never the corpus or model caches."""
from pathlib import Path
import zipfile


def package():
    code = Path(__file__).resolve().parent
    required = [code / "main.py", code / "README.md", code / "evaluation/evaluation_report.md",
                code / "evaluation/usage_report.md"]
    if any(not p.is_file() for p in required):
        raise RuntimeError("Run inference and evaluation before packaging")
    destination = code.parent / "code.zip"
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(code.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts: continue
            if path.suffix.lower() not in (".py", ".md", ".ps1", ".txt"): continue
            archive.write(path, path.relative_to(code.parent).as_posix())
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip(): raise RuntimeError("Archive integrity check failed")
        print(f"Created {destination} ({len(archive.namelist())} source/report files)")


if __name__ == "__main__": package()
