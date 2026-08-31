"""PhishingGuardAgent — 피싱 이메일·URL 위협 분석 멀티에이전트 (LangGraph)

정형 데이터(data/phishing_urls.csv)와 비정형 데이터(data/phishing_response_guide.pdf),
웹 검색(Tavily)을 함께 활용해 사용자의 질문 유형에 따라 5가지 경로로 라우팅되는
멀티에이전트 챗봇입니다. 자세한 그래프 구조는 README.md를 참고하세요.
"""
import os
import re
from typing import Optional

import pandas as pd
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.tools.tavily_search import TavilySearchResults
from langchain_community.vectorstores import FAISS
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict

from utils import python_code_parser, run_code

DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}\.[a-zA-Z]{2,}\b")


class State(TypedDict):
    question: str            # 사용자 질문 (원문)
    route: str                # 1차 라우팅 결과
    data: str                  # 조회/검색된 데이터
    code: str                   # 생성된 pandas 코드
    context: str                 # RAG로 검색된 가이드 문서 청크
    matched_pattern: bool         # [CE2] url_data_query 코드 실행 성공 여부
    suspicion_level: str           # [CE3] email_check 결과 (high / low)
    needs_web_check: bool           # [CE4] guideline_rag 이후 실시간 확인 필요 여부
    search_success: bool             # [CE5] web_search_agent 결과 획득 여부
    generation: str                   # 최종 답변


class PhishingGuardAgent:
    """피싱 URL 통계 / 이메일 분석 / 대응 가이드 RAG / 웹 위협 검색을 결합한 LangGraph 에이전트"""

    def __init__(
        self,
        api_key: str,
        tavily_api_key: Optional[str] = None,
        csv_path: str = None,
        pdf_path: str = None,
    ) -> None:
        _base = os.path.dirname(os.path.abspath(__file__))
        if csv_path is None:
            csv_path = os.path.join(_base, "data", "phishing_urls.csv")
        if pdf_path is None:
            pdf_path = os.path.join(_base, "data", "phishing_response_guide.pdf")
        self.llm = ChatOpenAI(model="gpt-4.1-mini", api_key=api_key)
        self.route_llm = ChatOpenAI(model="gpt-4.1-mini", api_key=api_key, temperature=0)
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small", api_key=api_key)

        # --- 정형 데이터: 피싱 URL 특징 데이터셋 ---
        self.df = pd.read_csv(csv_path)
        self.df_description = "피싱/정상 URL 구조적 특징 데이터셋 (시뮬레이션 데이터)"
        self.df_columns = list(self.df.columns)

        # --- 비정형 데이터: 피싱 대응 가이드 PDF → FAISS 벡터 스토어 ---
        pdf_name = os.path.splitext(pdf_path)[0]
        index_file_path = os.path.join(pdf_name, "index.faiss")
        if not os.path.exists(pdf_name):
            os.makedirs(pdf_name)

        if os.path.exists(index_file_path):
            self.vectorstore = FAISS.load_local(
                pdf_name, embeddings=self.embeddings, allow_dangerous_deserialization=True
            )
        else:
            docs = PyPDFLoader(pdf_path).load()
            self.vectorstore = FAISS.from_documents(docs, embedding=self.embeddings)
            self.vectorstore.save_local(pdf_name)

        self.db_retriever = self.vectorstore.as_retriever()

        # --- 웹 API 에이전트: Tavily 검색 ---
        if tavily_api_key:
            os.environ.setdefault("TAVILY_API_KEY", tavily_api_key)
        self.tavily_tool = TavilySearchResults(max_results=5)

        # =====================================================================
        # 그래프 구성 — 노드 7개 / 조건부 엣지(add_conditional_edges) 5개
        # =====================================================================
        graph = StateGraph(State)

        graph.add_node("router", self.route_question)
        graph.add_node("url_data_query", self.query_url_data)
        graph.add_node("email_check", self.check_email_text)
        graph.add_node("guideline_rag", self.retrieval)
        graph.add_node("web_search_agent", self.web_search)
        graph.add_node("risk_report", self.risk_report)
        graph.add_node("plain_answer", self.answer)

        graph.set_entry_point("router")

        # [CE1] 1차 라우팅 — 질문 유형에 따라 5갈래로 분기
        graph.add_conditional_edges(
            "router",
            lambda state: state["route"],
            {
                "url_data": "url_data_query",
                "email_check": "email_check",
                "guideline": "guideline_rag",
                "web_search": "web_search_agent",
                "plain": "plain_answer",
            },
        )

        # [CE2] pandas 코드가 정상 실행됐으면 대응 가이드까지 참고, 실패하면 바로 리포트
        graph.add_conditional_edges(
            "url_data_query",
            lambda state: "ok" if state["matched_pattern"] else "fail",
            {"ok": "guideline_rag", "fail": "risk_report"},
        )

        # [CE3] 이메일 의심도가 높으면 발신 도메인 등을 웹에서 추가 검증
        graph.add_conditional_edges(
            "email_check",
            lambda state: "high" if state["suspicion_level"] == "high" else "low",
            {"high": "web_search_agent", "low": "risk_report"},
        )

        # [CE4] 질문에 실제 도메인이 포함되어 실시간 평판 확인이 필요하면 웹 검색으로
        graph.add_conditional_edges(
            "guideline_rag",
            lambda state: "check" if state["needs_web_check"] else "skip",
            {"check": "web_search_agent", "skip": "risk_report"},
        )

        # [CE5] 웹 검색이 성공했으면 종합 리포트, 실패했으면 일반 답변으로 폴백
        graph.add_conditional_edges(
            "web_search_agent",
            lambda state: "ok" if state["search_success"] else "fail",
            {"ok": "risk_report", "fail": "plain_answer"},
        )

        graph.add_edge("risk_report", END)
        graph.add_edge("plain_answer", END)

        self.graph = graph.compile()

    def invoke(self, question: str) -> dict:
        return self.graph.invoke({"question": question})

    # ------------------------------------------------------------------
    # 노드 구현
    # ------------------------------------------------------------------

    def route_question(self, state: State):
        """[router] 질문을 5가지 경로 중 하나로 분류합니다."""
        print("---1차 라우팅---")
        route_system_message = (
            "당신은 사용자의 질문을 아래 5가지 경로 중 하나로 분류하는 라우팅 전문가입니다.\n"
            f"- url_data: {self.df_description}에 대한 통계·조회·집계 질문 "
            "(예: IP 주소를 포함한 피싱 URL 비율은?)\n"
            "- email_check: 사용자가 이메일/문자 본문(또는 그 일부)을 붙여넣거나 인용하며 "
            "피싱 여부·의심스러운 점 분석을 요청하는 경우. 본문 내용이 실제로 의심스러워 "
            "보이는지와 무관하게, '이거 피싱 맞아?', '분석해줘' 등 분석 요청 의도가 있으면 "
            "이 경로를 선택하세요.\n"
            "- guideline: 피싱 유형, 식별 체크리스트, 사고 대응 절차, 신고 방법 등 대응 가이드 관련 질문\n"
            "- web_search: 특정 도메인/사건/최신 동향에 대한 실시간 웹 검색이 필요한 질문\n"
            "- plain: 위 어디에도 해당하지 않는 일반 질문\n"
            "답변은 `route` key 하나만 있는 JSON으로 답변하고, 다른 텍스트나 설명을 생성하지 마세요."
        )
        route_prompt = ChatPromptTemplate.from_messages([
            ("system", route_system_message),
            ("human", "{question}"),
        ])
        chain = route_prompt | self.route_llm | JsonOutputParser()
        route = chain.invoke({"question": state["question"]})["route"].strip().lower()
        if route not in {"url_data", "email_check", "guideline", "web_search", "plain"}:
            route = "plain"
        return {"question": state["question"], "route": route}

    def query_url_data(self, state: State):
        """[url_data_query] 피싱 URL 데이터셋에 대한 pandas 코드를 생성·실행합니다."""
        print("---피싱 URL 데이터 조회---")
        system_message = (
            f"당신은 {self.df_description}를 분석하는 보안 데이터 분석가입니다.\n"
            f"`df` DataFrame에는 다음 열이 있습니다: {', '.join(self.df_columns)}\n"
            "label 열은 'phishing' 또는 'legitimate' 값을 가집니다.\n"
            "질문에 답할 수 있는 pandas 코드를 작성하고 반드시 print()로 결과를 출력하세요.\n"
            "데이터는 이미 로드되어 있으므로 데이터 로드 코드는 생략하세요."
        )
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_message),
            ("human", "{question}"),
        ])
        chain = (
            {"question": RunnablePassthrough()}
            | prompt
            | self.llm
            | StrOutputParser()
            | python_code_parser
        )
        code = chain.invoke(state["question"])
        data = run_code(code, df=self.df)
        matched_pattern = "Error" not in data
        return {
            "question": state["question"], "code": code, "data": data,
            "matched_pattern": matched_pattern,
        }

    def check_email_text(self, state: State):
        """[email_check] 사용자가 붙여넣은 이메일/문자 본문의 피싱 의심도를 분석합니다."""
        print("---이메일 본문 분석---")
        system_message = (
            "당신은 피싱 이메일을 분석하는 보안 분석가입니다.\n"
            "주어진 이메일/문자 본문에서 발신자 위장, 긴급성 유발 문구, 문법 오류, "
            "민감정보 요구, 의심스러운 링크·첨부파일 여부를 검토하세요.\n"
            "답변은 `suspicion_level`(\"high\" 또는 \"low\")과 `reasons`(근거 리스트) "
            "두 key만 있는 JSON으로 답변하세요."
        )
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_message),
            ("human", "{question}"),
        ])
        chain = prompt | self.llm | JsonOutputParser()
        result = chain.invoke({"question": state["question"]})
        suspicion_level = str(result.get("suspicion_level", "low")).strip().lower()
        reasons = result.get("reasons", [])
        data = "의심도: " + suspicion_level + "\n근거: " + "; ".join(reasons)
        return {"question": state["question"], "data": data, "suspicion_level": suspicion_level}

    def retrieval(self, state: State):
        """[guideline_rag] 피싱 대응 가이드 문서에서 관련 내용을 검색합니다."""
        print("---대응 가이드 검색---")
        docs = self.db_retriever.invoke(state["question"])
        context = "\n\n".join(doc.page_content for doc in docs)
        needs_web_check = bool(DOMAIN_PATTERN.search(state["question"]))
        return {"question": state["question"], "context": context, "needs_web_check": needs_web_check}

    def web_search(self, state: State):
        """[web_search_agent] Tavily로 도메인·사건 관련 최신 정보를 검색합니다."""
        print("---웹 위협 정보 검색---")
        try:
            results = self.tavily_tool.invoke({"query": state["question"]})
            search_success = bool(results)
            context = "\n".join(r.get("content", "") for r in results) if search_success else ""
        except Exception as e:
            search_success = False
            context = f"검색 오류: {e}"
        return {"question": state["question"], "context": context, "search_success": search_success}

    def risk_report(self, state: State):
        """[risk_report] 지금까지 모인 정보를 종합해 최종 답변과 위험도를 산출합니다."""
        print("---위험도 리포트 생성---")
        system_message = (
            "당신은 금융권 피싱 위협을 분석하는 보안 분석가입니다.\n"
            "아래 제공된 데이터/검색 결과에 근거하여 사용자의 질문에 답하세요.\n"
            "답변 마지막 줄에 반드시 '위험도: [정보성/낮음/보통/높음/치명적]' 형식으로 등급을 표기하세요.\n\n"
            f"--- 데이터/조회 결과 ---\n{state.get('data', '(없음)')}\n"
            f"--- 참고 문서/검색 결과 ---\n{state.get('context', '(없음)')}\n---"
        )
        messages = [
            SystemMessage(content=system_message),
            HumanMessage(content=state["question"]),
        ]
        generation = (self.llm | StrOutputParser()).invoke(messages)
        return {"question": state["question"], "generation": generation}

    def answer(self, state: State):
        """[plain_answer] 데이터/검색 없이 일반 질문에 직접 답하거나, 웹 검색 실패 시 폴백합니다."""
        print("---일반 답변---")
        generation = self.llm.invoke(state["question"]).content
        return {"question": state["question"], "generation": generation}
