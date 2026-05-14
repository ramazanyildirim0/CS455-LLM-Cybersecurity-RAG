"""
Layer 2: Parallel RAG retrieval across three FAISS indexes.

Two-stage retrieval:
  Stage 1 — Bi-encoder (all-MiniLM-L6-v2): retrieve top-20 per index via FAISS
  Stage 2 — Cross-encoder (ms-marco-MiniLM-L-6-v2): re-rank to top-5

Usage:
    from layer1.static_analysis import run_static_analysis
    from layer2.retrieval import Retriever

    findings  = run_static_analysis(code)
    retriever = Retriever()                       # load once; reuse across calls
    results   = retriever.query(code, findings)   # top-5 per index

Return value:
    {
        "security":    [ { ...chunk fields..., "score": float, "ce_score": float }, ... ],
        "style":       [ ... ],
        "bug_pattern": [ ... ],
    }
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import CrossEncoder, SentenceTransformer

from faiss_index.search import load_index

_MODEL_PATH       = Path(__file__).parent.parent / "models" / "all-MiniLM-L6-v2"
_CE_MODEL_PATH    = Path(__file__).parent.parent / "models" / "cross-encoder-ms-marco"
_CE_MODEL_HF_ID   = "cross-encoder/ms-marco-MiniLM-L-6-v2"
_INDEX_NAMES      = ["security", "style", "bug_pattern"]

# Bi-encoder retrieves this many candidates; cross-encoder re-ranks to top_k
_BIENCODER_CANDIDATES = 20

# Maps Bandit test IDs to focused semantic queries for the security index.
# Using descriptive vulnerability-type phrases gets far better retrieval than
# dumping raw code, because the index chunks contain rule descriptions not code.
_BANDIT_TO_QUERY: dict[str, str] = {
    "B608": "SQL injection Python raw string query user input parameterized prevent CWE-89",
    "B605": "OS command injection subprocess user input shell Python prevent CWE-78",
    "B602": "subprocess shell=True command injection user input Python insecure",
    "B601": "paramiko exec_command SSH injection Python user input",
    "B301": "pickle deserialization insecure arbitrary code execution Python CWE-502",
    "B403": "pickle module insecure deserialization import Python CWE-502",
    "B302": "pickle marshal loads insecure Python",
    "B506": "yaml.load unsafe FullLoader BaseLoader arbitrary code execution Python",
    "B105": "hardcoded password string literal Python CWE-259 credentials secret",
    "B106": "hardcoded password function argument Python CWE-259",
    "B107": "hardcoded password default argument Python CWE-259",
    "B108": "probable insecure temp file Python",
    "B303": "MD5 SHA1 weak broken hash Python CWE-327 cryptography",
    "B324": "hashlib MD5 SHA1 insecure Python weak cryptographic hash",
    "B311": "random insecure not cryptographically secure Python CWE-330 token",
    "B501": "SSL certificate verification disabled verify=False Python CWE-295",
    "B502": "ssl insecure protocol TLS version Python",
    "B503": "ssl weak cipher Python insecure",
    "B504": "ssl_with_no_version Python insecure",
    "B505": "weak RSA DSA key size Python cryptographic",
    "B307": "eval injection Python code injection CWE-95 user input",
    "B102": "exec injection Python code execution CWE-94 user input",
    "B411": "xmlrpc Python injection attack",
    "B201": "Flask debug mode enabled production Python insecure",
    "B703": "Django mark_safe XSS Python template injection CWE-79",
    "B704": "Jinja2 autoescape disabled XSS Python template CWE-79",
    "B320": "XML external entity XXE Python lxml CWE-611",
    "B410": "lxml XXE Python XML injection",
    "B413": "pycrypto insecure deprecated Python",
    "B322": "input Python 2 code injection",
    "B612": "logging config listen network Python insecure",
    "H001": "unvalidated Flask Django request input XSS injection Python CWE-20",
    "H002": "lxml XXE XML external entity Python resolve_entities defusedxml CWE-611",
    "H003": "JWT decode verify=False algorithm none signature bypass Python CWE-347",
    "H004": "hardcoded password comparison literal Python CWE-259 credentials",
}

# Maps CWE IDs to semantic queries when Bandit code not available
_CWE_TO_QUERY: dict[str, str] = {
    "CWE-89":  "SQL injection Python parameterized query prevent",
    "CWE-78":  "OS command injection subprocess shell Python prevent",
    "CWE-94":  "code injection exec Python arbitrary code execution prevent",
    "CWE-95":  "eval injection Python expression code execution prevent",
    "CWE-502": "insecure deserialization pickle yaml Python CWE-502 prevent",
    "CWE-259": "hardcoded credentials password Python secret management CWE-259",
    "CWE-798": "hardcoded credentials hard-coded Python CWE-798",
    "CWE-22":  "path traversal Python file open user input prevent CWE-22",
    "CWE-327": "weak cryptography MD5 SHA1 broken hash Python CWE-327",
    "CWE-330": "insecure random Python not cryptographic secure CWE-330",
    "CWE-295": "SSL certificate verification Python requests insecure CWE-295",
    "CWE-20":  "input validation Python user input sanitize CWE-20",
    "CWE-79":  "XSS cross-site scripting Python template HTML injection CWE-79",
    "CWE-918": "SSRF Python requests URL user input prevent CWE-918",
    "CWE-306": "missing authentication Python access control CWE-306",
    "CWE-611": "XXE XML external entity Python defusedxml CWE-611",
    "CWE-601": "open redirect Python URL validation CWE-601",
    "CWE-362": "race condition Python file thread CWE-362",
    "CWE-117": "log injection Python logging user input sanitize CWE-117",
    "CWE-347": "JWT signature verification Python decode algorithm none CWE-347",
    "CWE-329": "static IV AES cipher CBC Python predictable CWE-329",
    "CWE-1204": "static initialization vector AES CBC Python insecure CWE-1204",
    "CWE-259": "hardcoded password comparison Python literal credential CWE-259",
    "CWE-798": "hardcoded credential Python secret API key token CWE-798",
    "CWE-321": "hardcoded AES RSA cryptographic key Python literal bytes CWE-321",
    "CWE-434": "unrestricted file upload Python Flask no validation extension size CWE-434",
    "CWE-117": "log injection Python logging user input CRLF newline sanitize CWE-117",
    "CWE-730": "ReDoS regular expression denial of service Python catastrophic backtracking CWE-730",
    "CWE-319": "cleartext transmission sensitive data Python HTTP not HTTPS CWE-319",
    "CWE-200": "information exposure error message Python exception details CWE-200",
    "CWE-331": "insufficient entropy Python random module weak randomness CWE-331",
    "CWE-338": "predictable PRNG Python random seed cryptographic CWE-338",
    "CWE-339": "small seed space Python random os.urandom weak entropy CWE-339",
    "CWE-326": "inadequate encryption strength weak key size Python RSA CWE-326",
    "CWE-90":  "LDAP injection Python user input unsanitized directory query CWE-90",
    "CWE-703": "improper check exception handling Python TOCTOU file CWE-703",
    "CWE-209": "information in error messages Python exception traceback CWE-209",
    "CWE-116": "improper encoding escaping output Python regex HTML sanitization bleach markupsafe CWE-116",
    "CWE-595": "object reference identity comparison Python is operator value equality CWE-595",
}


def _search_index(index: faiss.Index, meta: list[dict], vec: np.ndarray, top_k: int) -> list[dict]:
    scores, ids = index.search(vec, top_k)
    results = []
    for score, idx in zip(scores[0], ids[0]):
        if idx == -1:
            continue
        hit = meta[idx].copy()
        hit["score"] = float(score)
        results.append(hit)
    return results


def _rerank(cross_encoder: CrossEncoder, query: str, candidates: list[dict], top_k: int) -> list[dict]:
    """Score (query, text_preview) pairs with the cross-encoder and return top_k."""
    texts = [c.get("text_preview") or c.get("title") or "" for c in candidates]
    pairs = [[query, t] for t in texts]
    ce_scores = cross_encoder.predict(pairs)

    for chunk, ce_score in zip(candidates, ce_scores):
        chunk["ce_score"] = float(ce_score)

    reranked = sorted(candidates, key=lambda c: c["ce_score"], reverse=True)
    return reranked[:top_k]


class Retriever:
    def __init__(self):
        self._model = SentenceTransformer(str(_MODEL_PATH))

        # Load cross-encoder from local path if downloaded, else from HF Hub
        ce_source = str(_CE_MODEL_PATH) if (_CE_MODEL_PATH / "config.json").exists() else _CE_MODEL_HF_ID
        self._cross_encoder = CrossEncoder(ce_source)

        self._indexes = {
            name: load_index(name) for name in _INDEX_NAMES
        }

    def _build_security_query(self, code: str, layer1_findings: list[dict]) -> str:
        """Build a focused semantic query for the security index.

        Priority order:
        1. Bandit-code-specific queries (most precise)
        2. CWE-specific queries
        3. Short code prefix fallback
        """
        query_parts: list[str] = []

        for f in layer1_findings:
            code_id = f.get("code", "")
            if code_id in _BANDIT_TO_QUERY:
                query_parts.append(_BANDIT_TO_QUERY[code_id])
            else:
                for cwe in f.get("cwe_ids") or []:
                    if cwe in _CWE_TO_QUERY:
                        query_parts.append(_CWE_TO_QUERY[cwe])

        if query_parts:
            # Deduplicate while preserving order
            seen: set[str] = set()
            unique: list[str] = []
            for q in query_parts:
                if q not in seen:
                    seen.add(q)
                    unique.append(q)
            # Join top-3 query parts to cover multiple finding types
            return " | ".join(unique[:3])

        # Fallback: use first 400 chars of code for general vulnerability search
        return "Python security vulnerability injection deserialization path traversal " + code[:400]

    def query(self, code: str, layer1_findings: list[dict], top_k: int = 5) -> dict:
        sec_query = self._build_security_query(code, layer1_findings)

        pylint_context = " ".join(
            f["message"] for f in layer1_findings if f["tool"] == "pylint"
        )
        style_query = (code[:300] + "\n" + pylint_context).strip() if pylint_context else code[:400]
        bug_query   = code[:400]

        vecs = self._model.encode(
            [sec_query, style_query, bug_query],
            normalize_embeddings=True,
        ).astype(np.float32)

        tasks = {
            "security":    (self._indexes["security"],    vecs[0:1], sec_query),
            "style":       (self._indexes["style"],       vecs[1:2], style_query),
            "bug_pattern": (self._indexes["bug_pattern"], vecs[2:3], bug_query),
        }

        # Stage 1: retrieve top-20 per index in parallel
        candidates: dict[str, list[dict]] = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(_search_index, index, meta, vec, _BIENCODER_CANDIDATES): name
                for name, ((index, meta), vec, _query) in tasks.items()
            }
            for future in as_completed(futures):
                candidates[futures[future]] = future.result()

        # Stage 2: cross-encoder re-rank to top_k per index
        results = {
            name: _rerank(self._cross_encoder, tasks[name][2], candidates[name], top_k)
            for name in _INDEX_NAMES
        }

        return results
