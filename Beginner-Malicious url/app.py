from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


SAFE_LABEL = "Safe"
MALICIOUS_LABEL = "Malicious"
TARGET_LABEL = "is_malicious"
RANDOM_STATE = 42

SPECIAL_CHARACTERS = [".", "-", "_", "/", "?", "=", "@", "&", "%"]
THREAT_KEYWORDS = ["login", "verify", "update", "bank", "secure", "account", "signin", "ebayisapi"]
COMMON_MULTIPART_TLDS = {"co.uk", "com.au", "co.nz", "co.jp", "com.br", "com.sg", "com.mx"}


@dataclass
class DashboardArtifacts:
    raw_dataset: pd.DataFrame
    engineered_dataset: pd.DataFrame
    summary_table: pd.DataFrame
    model: RandomForestClassifier
    detector: "URLThreatDetector"
    feature_columns: List[str]
    metrics: Dict[str, float]
    confusion: Dict[str, object]
    threshold: float


class SyntheticURLGenerator:
    """Generate a balanced corpus of realistic safe and malicious URLs."""

    def build_dataset(self, per_class: int = 60) -> pd.DataFrame:
        safe_urls = self._generate_safe_urls(per_class)
        malicious_urls = self._generate_malicious_urls(per_class)

        safe_frame = pd.DataFrame(
            {
                "url": safe_urls,
                "label": SAFE_LABEL,
                "category": [self._safe_category(url) for url in safe_urls],
            }
        )
        malicious_frame = pd.DataFrame(
            {
                "url": malicious_urls,
                "label": MALICIOUS_LABEL,
                "category": [self._malicious_category(url) for url in malicious_urls],
            }
        )

        dataset = pd.concat([safe_frame, malicious_frame], ignore_index=True)
        dataset[TARGET_LABEL] = (dataset["label"] == MALICIOUS_LABEL).astype(int)
        return dataset.drop_duplicates(subset=["url"]).reset_index(drop=True)

    def _generate_safe_urls(self, per_class: int) -> List[str]:
        bank_domains = [
            "northshorebank.com",
            "harbortrustbank.net",
            "citadelcreditunion.org",
            "bluewaterbanking.com",
            "aurorafinance.net",
        ]
        social_domains = [
            "socialbridge.io",
            "friendloop.app",
            "circlechat.social",
            "communitystream.net",
            "pixelpulse.app",
        ]
        shopping_domains = [
            "marketlane.shop",
            "cartvault.com",
            "primebasket.store",
            "urbancart.co",
            "checkoutlane.net",
        ]
        safe_templates = [
            (
                bank_domains,
                [
                    "https://www.{domain}/online-banking/dashboard?session={token}",
                    "https://secure.{domain}/login?service=accounts&ref={token}",
                    "https://portal.{domain}/accounts/overview/{token}",
                    "https://mobile.{domain}/cards/transactions?view={token}",
                ],
            ),
            (
                social_domains,
                [
                    "https://www.{domain}/feed/home?tab=for-you&v={token}",
                    "https://app.{domain}/messages/inbox/{token}",
                    "https://support.{domain}/help/articles/{token}",
                    "https://profile.{domain}/settings/privacy/{token}",
                ],
            ),
            (
                shopping_domains,
                [
                    "https://shop.{domain}/products/electronics/item-{token}",
                    "https://www.{domain}/cart/checkout?promo={token}",
                    "https://offers.{domain}/deals/today/{token}",
                    "https://help.{domain}/orders/tracking/{token}",
                ],
            ),
        ]

        urls: List[str] = []
        while len(urls) < per_class:
            domain_group, patterns = safe_templates[len(urls) % len(safe_templates)]
            domain = domain_group[len(urls) % len(domain_group)]
            template = patterns[len(urls) % len(patterns)]
            token = f"S{1000 + len(urls)}"
            urls.append(template.format(domain=domain, token=token))
        return urls[:per_class]

    def _generate_malicious_urls(self, per_class: int) -> List[str]:
        phishing_domains = [
            "secure-login-update.com",
            "banking-alerts.net",
            "account-verify-support.org",
            "signin-secure-help.com",
            "security-checkpoint.io",
        ]

        urls: List[str] = []
        while len(urls) < per_class:
            idx = len(urls)
            style = idx % 4
            if style == 0:
                host = phishing_domains[idx % len(phishing_domains)]
                urls.append(
                    f"http://www-{idx}.secure.{host}/verify/account/login.php?session={5000 + idx}&bank=update"
                )
            elif style == 1:
                host = phishing_domains[idx % len(phishing_domains)]
                urls.append(
                    f"https://login.{host}/signin/update/confirm?account={5000 + idx}&ref=ebayisapi"
                )
            elif style == 2:
                octet_a = 172
                octet_b = 16 + (idx % 8)
                octet_c = 20 + (idx % 60)
                octet_d = 10 + (idx % 120)
                urls.append(
                    f"http://{octet_a}.{octet_b}.{octet_c}.{octet_d}/secure/verify?id={5000 + idx}&bank=1"
                )
            else:
                urls.append(
                    f"https://{idx}.support-account-check.com/update/security/login/{5000 + idx}?signin=true"
                )
        return urls[:per_class]

    @staticmethod
    def _safe_category(url: str) -> str:
        if "/online-banking/" in url or "/cards/" in url:
            return "Banking"
        if "/feed/" in url or "/messages/" in url:
            return "Social"
        return "Shopping"

    @staticmethod
    def _malicious_category(url: str) -> str:
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", url):
            return "IP-Based Phishing"
        if "ref=ebayisapi" in url:
            return "Typosquat Phishing"
        return "Credential Harvesting"


class URLFeatureEngineer:
    """Extract lexical, structural, and threat-oriented URL features."""

    def __init__(self, threat_keywords: Sequence[str], special_characters: Sequence[str]) -> None:
        self.threat_keywords = tuple(threat_keywords)
        self.special_characters = tuple(special_characters)
        self._ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        self._ipv6_pattern = re.compile(r"^[0-9A-Fa-f:]+$")

    def transform(self, frame: pd.DataFrame) -> pd.DataFrame:
        engineered = frame.copy()
        parsed = engineered["url"].apply(self._parse_url)
        parsed_frame = pd.DataFrame(parsed.tolist(), index=engineered.index)
        engineered = pd.concat([engineered, parsed_frame], axis=1)

        engineered["url_length"] = engineered["url"].str.len()
        engineered["domain_length"] = engineered["host"].str.len().fillna(0).astype(int)
        engineered["path_length"] = engineered["path"].str.len().fillna(0).astype(int)
        engineered["tld_length"] = engineered["tld"].str.len().fillna(0).astype(int)
        engineered["url_entropy"] = engineered["url"].apply(self._shannon_entropy)
        engineered["subdomain_count"] = engineered["host"].apply(self._count_subdomains)
        engineered["is_ip_hostname"] = engineered["host"].apply(self._is_raw_ip_hostname).astype(int)

        for character in self.special_characters:
            safe_name = self._safe_name(character)
            column_name = f"count_{safe_name}"
            engineered[column_name] = engineered["url"].str.count(re.escape(character))

        count_columns = [f"count_{self._safe_name(character)}" for character in self.special_characters]
        engineered["special_char_total"] = engineered[count_columns].sum(axis=1)
        engineered["special_char_ratio"] = engineered["special_char_total"] / engineered["url_length"].replace(0, np.nan)

        lowered = engineered["url"].str.lower()
        for keyword in self.threat_keywords:
            column_name = f"kw_{self._safe_name(keyword)}"
            engineered[column_name] = lowered.str.contains(re.escape(keyword), regex=True).astype(int)

        keyword_columns = [f"kw_{self._safe_name(keyword)}" for keyword in self.threat_keywords]
        engineered["threat_keyword_hits"] = engineered[keyword_columns].sum(axis=1)
        engineered["threat_keyword_flag"] = (engineered["threat_keyword_hits"] > 0).astype(int)

        engineered = engineered.fillna(0)
        return engineered

    def transform_single(self, url: str) -> pd.DataFrame:
        return self.transform(pd.DataFrame({"url": [url], "label": ["Input"], "category": ["Input"], TARGET_LABEL: [0]}))

    def feature_columns(self, frame: pd.DataFrame) -> List[str]:
        excluded = {"url", "label", "category", TARGET_LABEL, "scheme", "host", "path", "query", "fragment", "tld"}
        return [column for column in frame.columns if column not in excluded]

    def _parse_url(self, url: str) -> Dict[str, object]:
        normalized = self._normalize_url(url)
        parsed = urlsplit(normalized)
        host = (parsed.hostname or "").lower()
        return {
            "scheme": parsed.scheme,
            "host": host,
            "path": parsed.path or "",
            "query": parsed.query or "",
            "fragment": parsed.fragment or "",
            "tld": self._extract_tld(host),
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        candidate = str(url).strip()
        if not candidate:
            return "http://"
        if "//" not in candidate:
            candidate = f"http://{candidate}"
        return candidate

    def _extract_tld(self, host: str) -> str:
        if not host:
            return ""
        labels = host.split(".")
        if len(labels) >= 2:
            last_two = ".".join(labels[-2:])
            if last_two in COMMON_MULTIPART_TLDS:
                return last_two
        return labels[-1] if labels else ""

    def _count_subdomains(self, host: str) -> int:
        if not host or self._is_raw_ip_hostname(host):
            return 0
        labels = host.split(".")
        if len(labels) <= 2:
            return 0
        if ".".join(labels[-2:]) in COMMON_MULTIPART_TLDS and len(labels) > 3:
            return len(labels) - 3
        return len(labels) - 2

    def _is_raw_ip_hostname(self, host: str) -> bool:
        if not host:
            return False
        if self._ipv4_pattern.match(host):
            try:
                ipaddress.IPv4Address(host)
                return True
            except ipaddress.AddressValueError:
                return False
        if self._ipv6_pattern.match(host) and ":" in host:
            try:
                ipaddress.IPv6Address(host)
                return True
            except ipaddress.AddressValueError:
                return False
        return False

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        text = str(value)
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _safe_name(value: str) -> str:
        return (
            value.replace(".", "dot")
            .replace("-", "dash")
            .replace("_", "underscore")
            .replace("/", "slash")
            .replace("?", "qmark")
            .replace("=", "eq")
            .replace("@", "at")
            .replace("&", "amp")
            .replace("%", "pct")
        )


class URLThreatDetector:
    """Train, evaluate, and score URLs with a conservative Random Forest model."""

    def __init__(self, threshold: float = 0.60) -> None:
        self.threshold = threshold
        self.model = RandomForestClassifier(
            n_estimators=400,
            max_depth=8,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight={0: 1.15, 1: 0.85},
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )

    def fit(self, x_train: pd.DataFrame, y_train: pd.Series) -> None:
        self.model.fit(x_train, y_train)

    def evaluate(self, x_test: pd.DataFrame, y_test: pd.Series) -> Tuple[Dict[str, float], Dict[str, object]]:
        malicious_probability = self.model.predict_proba(x_test)[:, 1]
        y_pred = (malicious_probability >= self.threshold).astype(int)

        metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        }

        matrix = confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist()
        confusion = {
            "labels": [SAFE_LABEL, MALICIOUS_LABEL],
            "matrix": matrix,
            "rows": ["Actual Safe", "Actual Malicious"],
            "columns": ["Pred Safe", "Pred Malicious"],
        }
        return metrics, confusion

    def predict_single(self, feature_row: pd.DataFrame) -> Tuple[str, float]:
        malicious_probability = float(self.model.predict_proba(feature_row)[:, 1][0])
        label = MALICIOUS_LABEL if malicious_probability >= self.threshold else SAFE_LABEL
        return label, malicious_probability


def create_grouped_summary(frame: pd.DataFrame, numeric_columns: Sequence[str]) -> pd.DataFrame:
    def q25(series: pd.Series) -> float:
        return float(series.quantile(0.25))

    def q75(series: pd.Series) -> float:
        return float(series.quantile(0.75))

    q25.__name__ = "q25"
    q75.__name__ = "q75"

    summary = frame.groupby("label")[list(numeric_columns)].agg(["mean", "median", "std", q25, q75])
    summary.columns = [f"{metric}__{stat}" for metric, stat in summary.columns]
    return summary.reset_index()


@st.cache_resource(show_spinner=False)
def build_dashboard_artifacts() -> DashboardArtifacts:
    generator = SyntheticURLGenerator()
    engineer = URLFeatureEngineer(THREAT_KEYWORDS, SPECIAL_CHARACTERS)
    detector = URLThreatDetector(threshold=0.60)

    raw_dataset = generator.build_dataset(per_class=60)
    engineered_dataset = engineer.transform(raw_dataset)
    feature_columns = engineer.feature_columns(engineered_dataset)

    model_frame = engineered_dataset[feature_columns + [TARGET_LABEL]].copy()
    x_train, x_test, y_train, y_test = train_test_split(
        model_frame[feature_columns],
        model_frame[TARGET_LABEL],
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=model_frame[TARGET_LABEL],
    )

    detector.fit(x_train, y_train)
    metrics, confusion = detector.evaluate(x_test, y_test)

    summary_numeric_columns = [
        "url_length",
        "domain_length",
        "path_length",
        "tld_length",
        "url_entropy",
        "subdomain_count",
        "is_ip_hostname",
        "special_char_total",
        "special_char_ratio",
        "threat_keyword_hits",
    ] + [f"count_{URLFeatureEngineer._safe_name(char)}" for char in SPECIAL_CHARACTERS]

    summary_table = create_grouped_summary(engineered_dataset, summary_numeric_columns)

    return DashboardArtifacts(
        raw_dataset=raw_dataset,
        engineered_dataset=engineered_dataset,
        summary_table=summary_table,
        model=detector.model,
        detector=detector,
        feature_columns=feature_columns,
        metrics=metrics,
        confusion=confusion,
        threshold=detector.threshold,
    )


def gaussian_kde_trace(values: Sequence[float], x_grid: np.ndarray, bandwidth: float = 1.15) -> np.ndarray:
    array = np.asarray(values, dtype=float)
    if array.size == 0:
        return np.zeros_like(x_grid)
    if array.size > 1:
        std = float(np.std(array, ddof=1))
    else:
        std = float(np.std(array))
    scale = max(std, 1.0)
    bandwidth = max(bandwidth * scale, 0.75)
    diff = (x_grid[:, None] - array[None, :]) / bandwidth
    density = np.exp(-0.5 * diff**2).sum(axis=1)
    density /= array.size * bandwidth * math.sqrt(2 * math.pi)
    return density


def render_css() -> None:
    st.markdown(
        """
        <style>
            .stApp {
                background:
                    radial-gradient(circle at top left, rgba(23, 37, 84, 0.45), transparent 32%),
                    radial-gradient(circle at top right, rgba(4, 120, 87, 0.22), transparent 26%),
                    linear-gradient(180deg, #0b1120 0%, #0f172a 45%, #111827 100%);
                color: #e5eefb;
            }
            [data-testid="stSidebar"] {
                background: linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(17, 24, 39, 0.98));
                border-right: 1px solid rgba(148, 163, 184, 0.18);
            }
            .dashboard-title {
                font-size: 2.1rem;
                font-weight: 800;
                letter-spacing: 0.02em;
                margin-bottom: 0.15rem;
            }
            .dashboard-subtitle {
                color: #cbd5e1;
                margin-bottom: 1rem;
            }
            .card-block {
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 16px;
                background: linear-gradient(180deg, rgba(15, 23, 42, 0.88), rgba(30, 41, 59, 0.9));
                box-shadow: 0 16px 42px rgba(0, 0, 0, 0.28);
                padding: 1rem 1rem 0.85rem 1rem;
            }
            .metric-label {
                color: #94a3b8;
                font-size: 0.8rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                margin-bottom: 0.3rem;
            }
            .metric-value {
                font-size: 1.8rem;
                font-weight: 800;
                color: #f8fafc;
            }
            .metric-caption {
                color: #cbd5e1;
                font-size: 0.82rem;
                margin-top: 0.25rem;
            }
            .stPlotlyChart {
                border-radius: 16px;
                overflow: hidden;
                border: 1px solid rgba(148, 163, 184, 0.14);
            }
            div[data-testid="stDataFrame"] {
                border: 1px solid rgba(148, 163, 184, 0.14);
                border-radius: 16px;
                overflow: hidden;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(label: str, value: str, caption: str) -> None:
    st.markdown(
        f"""
        <div class="card-block">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-caption">{caption}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_length_distribution_figure(frame: pd.DataFrame) -> go.Figure:
    figure = go.Figure()
    colors = {SAFE_LABEL: "#4ade80", MALICIOUS_LABEL: "#fb7185"}
    x_min = int(frame["url_length"].min())
    x_max = int(frame["url_length"].max())
    x_grid = np.linspace(x_min - 2, x_max + 2, 300)

    for label in [SAFE_LABEL, MALICIOUS_LABEL]:
        subset = frame[frame["label"] == label]["url_length"]
        figure.add_trace(
            go.Histogram(
                x=subset,
                name=f"{label} Histogram",
                histnorm="probability density",
                opacity=0.45,
                marker_color=colors[label],
                nbinsx=18,
            )
        )
        figure.add_trace(
            go.Scatter(
                x=x_grid,
                y=gaussian_kde_trace(subset.to_numpy(), x_grid),
                mode="lines",
                name=f"{label} Density",
                line=dict(color=colors[label], width=3),
            )
        )

    figure.update_layout(
        barmode="overlay",
        template="plotly_dark",
        title="URL Length Distribution by Safety Class",
        xaxis_title="URL Length",
        yaxis_title="Density",
        legend_title_text="Series",
        height=420,
        margin=dict(l=20, r=20, t=60, b=20),
    )
    return figure


def build_special_character_figure(frame: pd.DataFrame) -> go.Figure:
    chart = go.Figure()
    colors = {SAFE_LABEL: "#60a5fa", MALICIOUS_LABEL: "#f97316"}
    char_columns = [(character, f"count_{URLFeatureEngineer._safe_name(character)}") for character in SPECIAL_CHARACTERS]

    for label in [SAFE_LABEL, MALICIOUS_LABEL]:
        subset = frame[frame["label"] == label]
        means = [float(subset[column].mean()) for _, column in char_columns]
        chart.add_trace(
            go.Bar(
                y=SPECIAL_CHARACTERS,
                x=means,
                name=label,
                orientation="h",
                marker_color=colors[label],
                text=[f"{value:.2f}" for value in means],
                textposition="auto",
            )
        )

    chart.update_layout(
        template="plotly_dark",
        barmode="group",
        title="Average Special Character Occurrences by Class",
        xaxis_title="Average Count",
        yaxis_title="Special Character",
        legend_title_text="Class",
        height=420,
        margin=dict(l=20, r=20, t=60, b=20),
    )
    return chart


def analyze_input_url(url: str, engineer: URLFeatureEngineer, detector: URLThreatDetector, feature_columns: Sequence[str]) -> Tuple[pd.DataFrame, str, float]:
    engineered = engineer.transform_single(url)
    feature_row = engineered.loc[:, list(feature_columns)]
    label, probability = detector.predict_single(feature_row)
    return engineered, label, probability


def render_sidebar(artifacts: DashboardArtifacts, engineer: URLFeatureEngineer) -> Tuple[pd.DataFrame, str, float, pd.DataFrame]:
    st.sidebar.title("Malicious URL Lens")
    st.sidebar.caption("Live lexical analysis and threat scoring")
    input_url = st.sidebar.text_input(
        "Enter a URL for instant analysis",
        placeholder="https://example.com/login?session=123",
    )

    verdict_label = ""
    malicious_probability = 0.0
    analyzed_frame = pd.DataFrame()

    if input_url.strip():
        analyzed_frame, verdict_label, malicious_probability = analyze_input_url(
            input_url, engineer, artifacts.detector, artifacts.feature_columns
        )
        if verdict_label == SAFE_LABEL:
            st.sidebar.success(f"Safety verdict: {verdict_label}")
        else:
            st.sidebar.error(f"Safety verdict: {verdict_label}")
        st.sidebar.caption(f"Malicious probability: {malicious_probability:.1%}")

        display_columns = [
            "url_length",
            "domain_length",
            "path_length",
            "tld_length",
            "url_entropy",
            "subdomain_count",
            "is_ip_hostname",
            "special_char_total",
            "special_char_ratio",
            "threat_keyword_hits",
        ]
        st.sidebar.markdown("**URL Feature Snapshot**")
        st.sidebar.dataframe(
            analyzed_frame[display_columns].T.rename(columns={0: "value"}),
            use_container_width=True,
            height=360,
        )
    else:
        st.sidebar.info("Type a URL to score it immediately.")

    st.sidebar.markdown("---")
    st.sidebar.subheader("Dataset Filters")
    category_filter = st.sidebar.multiselect(
        "Safety Class",
        options=[SAFE_LABEL, MALICIOUS_LABEL],
        default=[SAFE_LABEL, MALICIOUS_LABEL],
    )
    theme_filter = st.sidebar.multiselect(
        "URL Theme",
        options=sorted(artifacts.engineered_dataset["category"].unique().tolist()),
        default=sorted(artifacts.engineered_dataset["category"].unique().tolist()),
    )
    search_term = st.sidebar.text_input("Search substring", placeholder="bank, login, secure, etc.")
    length_range = st.sidebar.slider(
        "URL length range",
        min_value=int(artifacts.engineered_dataset["url_length"].min()),
        max_value=int(artifacts.engineered_dataset["url_length"].max()),
        value=(
            int(artifacts.engineered_dataset["url_length"].min()),
            int(artifacts.engineered_dataset["url_length"].max()),
        ),
    )

    filtered = artifacts.engineered_dataset.copy()
    filtered = filtered[filtered["label"].isin(category_filter)]
    filtered = filtered[filtered["category"].isin(theme_filter)]
    if search_term.strip():
        filtered = filtered[filtered["url"].str.contains(search_term, case=False, regex=False)]
    filtered = filtered[(filtered["url_length"] >= length_range[0]) & (filtered["url_length"] <= length_range[1])]

    return filtered, verdict_label, malicious_probability, analyzed_frame


def main() -> None:
    st.set_page_config(
        page_title="Malicious URL Analytics & Detection Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    render_css()

    artifacts = build_dashboard_artifacts()
    engineer = URLFeatureEngineer(THREAT_KEYWORDS, SPECIAL_CHARACTERS)

    st.markdown('<div class="dashboard-title">Malicious URL Analytics & Detection Dashboard</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="dashboard-subtitle">Executive-grade exploration of synthetic URL threat patterns, engineered lexical intelligence, and conservative phishing detection.</div>',
        unsafe_allow_html=True,
    )

    filtered_dataset, verdict_label, malicious_probability, analyzed_frame = render_sidebar(artifacts, engineer)

    st.markdown("### Executive Overview")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric_card("Total Dataset Size", f"{len(artifacts.engineered_dataset):,}", "Balanced synthetic corpus")
    with col2:
        prevalence = artifacts.engineered_dataset[TARGET_LABEL].mean() * 100
        render_metric_card("Base Malicious Prevalence", f"{prevalence:.1f}%", "Prior rate in generated set")
    with col3:
        render_metric_card("Model Accuracy", f"{artifacts.metrics['accuracy']:.3f}", "Holdout test performance")
    with col4:
        render_metric_card("Model F1-Score", f"{artifacts.metrics['f1']:.3f}", "Phishing detection balance")

    st.markdown("### Comparative Feature Analytics")
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.plotly_chart(build_length_distribution_figure(artifacts.engineered_dataset), use_container_width=True)
    with chart_col2:
        st.plotly_chart(build_special_character_figure(artifacts.engineered_dataset), use_container_width=True)

    st.markdown("### Raw Feature Matrix & Profile Breakdown")
    data_col, stats_col = st.columns([1.45, 1])
    with data_col:
        st.caption("The table below respects the active sidebar filters and exposes the full engineered dataset.")
        st.dataframe(
            filtered_dataset[
                [
                    "url",
                    "label",
                    "category",
                    "url_length",
                    "domain_length",
                    "path_length",
                    "tld_length",
                    "url_entropy",
                    "subdomain_count",
                    "is_ip_hostname",
                    "special_char_total",
                    "special_char_ratio",
                    "threat_keyword_hits",
                ]
            ],
            use_container_width=True,
            height=520,
        )
    with stats_col:
        with st.expander("Grouped descriptive statistics by class", expanded=True):
            st.dataframe(artifacts.summary_table, use_container_width=True, height=520)
        with st.expander("Model diagnostics", expanded=False):
            st.json(
                {
                    "accuracy": artifacts.metrics["accuracy"],
                    "precision": artifacts.metrics["precision"],
                    "recall": artifacts.metrics["recall"],
                    "f1": artifacts.metrics["f1"],
                    "confusion_matrix": artifacts.confusion,
                    "decision_threshold": artifacts.threshold,
                }
            )

    st.markdown("### Live Analyzer Output")
    if verdict_label:
        if verdict_label == SAFE_LABEL:
            st.success(f"Verdict: {verdict_label} | Malicious probability: {malicious_probability:.1%}")
        else:
            st.error(f"Verdict: {verdict_label} | Malicious probability: {malicious_probability:.1%}")
        st.dataframe(analyzed_frame, use_container_width=True, height=260)
    else:
        st.info("Enter a URL in the sidebar to see an instant lexical risk assessment.")


if __name__ == "__main__":
    main()