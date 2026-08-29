"""LLM이 생성한 Python 코드를 파싱/실행하기 위한 유틸리티 함수."""
import contextlib
import io


def python_code_parser(text: str) -> str:
    """LLM 응답에서 ```python ... ``` 코드 블록만 추출합니다."""
    if "```python" in text:
        text = text.split("```python")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    return text.strip()


def run_code(code: str, **local_vars) -> str:
    """Python 코드를 실행하고 stdout 출력을 문자열로 반환합니다."""
    stdout_capture = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_capture):
            exec(code, {}, dict(local_vars))
        output = stdout_capture.getvalue()
        return output if output else "코드가 실행되었지만 출력이 없습니다."
    except Exception as e:
        return f"Error: {e}"
