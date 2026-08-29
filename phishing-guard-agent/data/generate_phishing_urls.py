"""phishing_urls.csv 생성 스크립트

실제 피싱 URL 탐지 연구(UCI Phishing Websites 데이터셋 등)에서 널리 쓰이는 특징들을
참고하여, 정상/피싱 URL의 통계적 특성 차이를 반영한 시뮬레이션 데이터를 생성합니다.
(수업에서 사용한 security_logs.csv와 동일한 방식의 "시뮬레이션 데이터"입니다.)

실행: python generate_phishing_urls.py
"""
import numpy as np
import pandas as pd

SEED = 42
N_ROWS = 800
PHISHING_RATIO = 0.4

SUSPICIOUS_KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "confirm"]
LEGIT_DOMAINS = ["shinhanbank.com", "kbstar.com", "wooribank.com", "hanabank.com", "nonghyup.com"]
TLDS_PHISHING = ["tk", "xyz", "top", "click", "gq", "ml"]
TLDS_LEGIT = ["com", "co.kr", "net", "org"]


def _sample_url_id(i: int) -> str:
    return f"URL-{i:06d}"


def generate(n_rows: int = N_ROWS, phishing_ratio: float = PHISHING_RATIO, seed: int = SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n_phishing = int(n_rows * phishing_ratio)
    n_legit = n_rows - n_phishing

    rows = []
    for i in range(n_rows):
        is_phishing = i < n_phishing

        if is_phishing:
            url_length = int(rng.normal(75, 20))
            has_ip_address = rng.random() < 0.28
            has_at_symbol = rng.random() < 0.12
            num_subdomains = rng.integers(1, 5)
            num_hyphens = rng.integers(1, 6)
            num_digits = rng.integers(2, 12)
            uses_https = rng.random() < 0.35
            suspicious_https_token = rng.random() < 0.22
            is_shortened_url = rng.random() < 0.25
            domain_age_days = int(rng.exponential(45))
            has_suspicious_keyword = rng.random() < 0.65
            ssl_certificate_valid = rng.random() < 0.25
            redirect_count = rng.integers(0, 5)
            external_favicon = rng.random() < 0.55
            anchor_mismatch_ratio = round(float(rng.uniform(0.3, 0.95)), 2)
            tld = rng.choice(TLDS_PHISHING)
            domain = f"{rng.choice(SUSPICIOUS_KEYWORDS)}-{'secure' if suspicious_https_token else 'page'}{rng.integers(10, 999)}.{tld}"
            label = "phishing"
        else:
            url_length = int(rng.normal(35, 10))
            has_ip_address = rng.random() < 0.01
            has_at_symbol = rng.random() < 0.01
            num_subdomains = rng.integers(0, 2)
            num_hyphens = rng.integers(0, 2)
            num_digits = rng.integers(0, 4)
            uses_https = rng.random() < 0.96
            suspicious_https_token = rng.random() < 0.01
            is_shortened_url = rng.random() < 0.03
            domain_age_days = int(rng.normal(2200, 800))
            has_suspicious_keyword = rng.random() < 0.08
            ssl_certificate_valid = rng.random() < 0.97
            redirect_count = rng.integers(0, 2)
            external_favicon = rng.random() < 0.05
            anchor_mismatch_ratio = round(float(rng.uniform(0.0, 0.15)), 2)
            domain = rng.choice(LEGIT_DOMAINS)
            label = "legitimate"

        url_length = max(12, url_length)
        domain_age_days = max(0, domain_age_days)
        scheme = "https" if uses_https else "http"

        rows.append({
            "url_id": _sample_url_id(i + 1),
            "url": f"{scheme}://{domain}/",
            "url_length": url_length,
            "has_ip_address": int(has_ip_address),
            "has_at_symbol": int(has_at_symbol),
            "num_subdomains": int(num_subdomains),
            "num_hyphens": int(num_hyphens),
            "num_digits": int(num_digits),
            "uses_https": int(uses_https),
            "suspicious_https_token": int(suspicious_https_token),
            "is_shortened_url": int(is_shortened_url),
            "domain_age_days": domain_age_days,
            "has_suspicious_keyword": int(has_suspicious_keyword),
            "ssl_certificate_valid": int(ssl_certificate_valid),
            "redirect_count": int(redirect_count),
            "external_favicon": int(external_favicon),
            "anchor_mismatch_ratio": anchor_mismatch_ratio,
            "label": label,
        })

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = generate()
    out_path = "phishing_urls.csv"
    df.to_csv(out_path, index=False)
    print(f"생성 완료: {out_path} ({len(df)}행, phishing={sum(df.label == 'phishing')}, legitimate={sum(df.label == 'legitimate')})")
