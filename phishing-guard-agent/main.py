import os

import streamlit as st
from dotenv import load_dotenv

from phishing_agent import PhishingGuardAgent

load_dotenv()


def _get_secret(key: str) -> str:
    """로컬(.env)과 Streamlit Cloud(st.secrets) 양쪽 모두에서 값을 읽습니다."""
    value = os.getenv(key)
    if value:
        return value
    try:
        return st.secrets[key]
    except Exception:
        return ""


OPENAI_API_KEY = _get_secret("OPENAI_API_KEY")
TAVILY_API_KEY = _get_secret("TAVILY_API_KEY")

st.set_page_config(page_title="피싱 가드 에이전트", page_icon="🎣", layout="wide", initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
    .hero {
        padding: 2rem 2.2rem;
        border-radius: 18px;
        background: linear-gradient(135deg, #7C2D12 0%, #9A3412 45%, #B45309 100%);
        color: #FFF7ED;
        margin-bottom: 1.6rem;
        box-shadow: 0 10px 30px rgba(154, 52, 18, 0.35);
    }
    .hero h1 { margin: 0; font-size: 2rem; color: #FFF7ED; }
    .hero p { margin: 0.4rem 0 0 0; opacity: 0.9; font-size: 1rem; color: #FFF7ED; }
    div[data-testid="stChatMessage"] { border-radius: 14px; }
    </style>
    <div class="hero">
        <h1>🎣 피싱 가드 에이전트</h1>
        <p>피싱 URL 통계 · 이메일 본문 분석 · 대응 가이드(RAG) · 실시간 웹 위협 검색을 결합한 멀티에이전트 챗봇입니다.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("환경 설정 상태")
    if OPENAI_API_KEY:
        st.success("OpenAI API Key: 로드됨")
    else:
        st.error("OpenAI API Key가 설정되지 않았습니다.")
    if TAVILY_API_KEY:
        st.success("Tavily API Key: 로드됨")
    else:
        st.warning("Tavily API Key가 설정되지 않았습니다. (web_search 경로 비활성)")
    st.caption("키는 로컬 `.env` 또는 Streamlit Cloud Secrets에서 자동으로 로드됩니다.")

    st.divider()
    st.subheader("💡 질문 예시")
    st.markdown(
        "- **url_data**: IP 주소를 포함한 피싱 URL 비율은?\n"
        "- **email_check**: (이메일 본문 붙여넣고) 이거 피싱 맞아?\n"
        "- **guideline**: 피싱 이메일을 열었을 때 대응 절차 알려줘\n"
        "- **web_search**: kbstar-secure-login123.tk 관련 위협 정보 있어?\n"
        "- **plain**: 오늘 날씨 어때?"
    )

    if st.button("🗑️ 대화 초기화", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

if not OPENAI_API_KEY:
    st.warning("`.env` 파일(로컬) 또는 Secrets(배포)에 `OPENAI_API_KEY`를 설정해주세요.")
    st.stop()


@st.cache_resource
def init_agent(_openai_key: str, _tavily_key: str):
    return PhishingGuardAgent(api_key=_openai_key, tavily_api_key=_tavily_key)


if "agent" not in st.session_state:
    with st.spinner("에이전트 초기화 중입니다 (최초 1회, PDF 임베딩 포함 약 1분 소요)..."):
        st.session_state.agent = init_agent(OPENAI_API_KEY, TAVILY_API_KEY)
    st.success("에이전트 초기화를 완료했습니다.")

if "messages" not in st.session_state:
    st.session_state.messages = []

for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

if prompt := st.chat_input("피싱 URL/이메일/대응 절차에 대해 물어보세요."):
    with st.chat_message("user"):
        st.markdown(prompt)
    st.session_state.messages.append({"role": "user", "content": prompt})

    with st.chat_message("assistant"):
        with st.spinner("분석 중..."):
            response = st.session_state.agent.invoke(prompt)
        generation = response["generation"]
        st.markdown(generation)

    st.session_state.messages.append({"role": "assistant", "content": generation})
