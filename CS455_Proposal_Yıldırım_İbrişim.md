**CS 455 / CS 555 — Project Proposal**

*Large Language Models — Spring 2025/2026*

# **Section 1 — Group Members**

List all group members in the exact format below. Groups must have 2 or 3 members.

*Ramazan\_Yıldırım, 32501*

*Arman\_İbrişim, 32014* 

# **Section 2 — Track**

State explicitly which ONE of the following applies to your group. Delete the lines that do not apply, or simply write your selected track in plain text.

* CS 455 Project

* CS 555 Project

* Paper Track Application (open to CS 455 and CS 555\) — optional

**Our track:** *CS 455 Project*

**If applying for the Paper Track, briefly explain (2–4 sentences) why your group is suited for it: prior research/coursework, technical strengths, and the additional ambition you bring to the project. Leave blank if you are on the standard CS 455 or CS 555 track.**

# **Section 3 — Project Proposal**

## **3.1 Project Title**

*PythonGuard: A Security-Focused RAG System for Automated Python Code Review*

## **3.2 Project Category**

Indicate which category your project belongs to (A, B, C, D, E, or Other). If "Other," provide a brief justification.

*(A) Application / System Building — with a strong (C) Evaluation component. The system builds a production-style RAG pipeline and evaluates it rigorously against static analysis baselines.*

## **3.3 Problem Definition**

Define the problem you are tackling. Be specific. Avoid vague descriptions like "we will build a chatbot." State exactly what input the system takes, what output it produces, and what success looks like.

*The system takes a Python code snippet or function as input and produces a structured JSON list of issues, where each issue includes: the line number, a severity label (CRITICAL / WARNING / INFO), a natural-language explanation, a concrete fix suggestion, and a citation to the specific rule or vulnerability database entry (e.g. CWE-89, Bandit B608, PEP 8\) that grounds the finding. Success means the system correctly identifies known vulnerability classes in Python code — such as SQL injection, command injection, hardcoded secrets, weak cryptography, and unsafe deserialization — while producing a lower false positive rate and higher citation accuracy than a zero-shot LLM baseline. Algorithmic correctness and business-logic errors are explicitly out of scope.*

## **3.4 Motivation**

Why is this problem important and why is it interesting? Who would benefit from a solution? What is currently missing in existing approaches?

*Python is among the most widely used languages for web backends, data pipelines, and AI systems, yet many Python developers lack formal security training. Existing static analysis tools (pylint, bandit) catch known patterns but produce findings with minimal explanation, making them hard to act on. General-purpose LLMs can explain vulnerabilities but hallucinate citations and miss pattern-specific rules. A RAG-based reviewer bridges this gap: it grounds every finding in a retrieved security rule, making the output both explainable and verifiable. This is directly relevant to the real-world AI product landscape; grounded, citation-aware generation is one of the core open problems in deploying LLMs in production.*

## **3.5 Approach**

Describe your technical approach. Which model(s) will you use (e.g., BERT-based, GPT-based, Llama, Turkish models, etc.)? Which techniques (fine-tuning, RAG, prompting, LoRA, etc.)? What is the architecture or pipeline?

*The pipeline has three sequential layers. In Layer 1, the input code is first passed through two deterministic static analysis tools — Bandit (security linter) and pylint (style and logic checker) — whose structured JSON output is captured and forwarded downstream. This layer catches high-confidence, well-defined violations without LLM cost.*

*In Layer 2, the code snippet is embedded using the all-MiniLM-L6-v2 sentence transformer model and queried against three separate FAISS vector indexes: (i) a Security Index built from Semgrep Python security YAML rules, CWE XML entries filtered to Python-relevant weaknesses, and OWASP Cheat Sheet markdown files (\~2,000 total chunks from existing public sources); (ii) a Style Index built from PEP 8, PEP 257, and PEP 484; and (iii) a Bug Pattern Index built from the Dahoas and Muennighoff HuggingFace datasets. Each index is queried in parallel, returning the top-5 most relevant chunks per index.*

*In Layer 3, a prompt builder assembles the original code, the static analysis tool output from Layer 1, and the retrieved chunks from Layer 2 into a structured prompt. We will use a locally-run open-source LLM — candidates include Qwen2.5, Llama 3.1, and Mistral — and will evaluate which model produces the most consistent structured JSON output before settling on a final choice. The LLM is instructed to produce a JSON array of issues where each issue cites the specific retrieved rule that grounds it; findings without a retrievable citation are labeled 'heuristic'. A lightweight Gradio interface allows interactive demonstration on arbitrary input.*

## **3.6 Data**

What data will you use? Specify the dataset name(s), source(s), size, and language. If you are scraping or using private/institutional data, state how you will obtain permission and address ethical/legal considerations.

*The Security Index (\~2,000 chunks) is assembled from three existing public sources: (1) semgrep/semgrep-rules Python security YAML files cloned from GitHub (github.com/semgrep/semgrep-rules, python/security/), yielding \~400 rules; (2) third-party Semgrep rule collections (trailofbits/semgrep-rules, elttam/semgrep-rules) aggregated via semgrep-rules-manager, adding \~140 additional Python rules; and (3) the CWE full XML database filtered to \~50 Python-relevant entries (cwe.mitre.org/data/xml/cwec\_latest.xml.zip), each parsed into a structured chunk containing the weakness description, consequences, and mitigation. No LLM-synthesized data is used; all chunks come directly from existing authoritative sources. The Style Index (\~300 chunks) is built from PEP 8, PEP 257, and PEP 484 scraped from peps.python.org, chunked by section. The Bug Pattern Index uses two public HuggingFace datasets: Dahoas/code-review-instruct-critique-revision-python (9,460 rows, filtered to security and logic-relevant critiques) and Muennighoff/python-bugs (1,000 rows of buggy/fixed pairs with bug type labels). For evaluation, we use bigcode/humanevalpack Python split (163 test cases with labeled bug types) and Tomo-Melb/CodeReviewQA Python subset (100 manually annotated real-world review examples). All datasets are publicly available; no private or institutional data is used.*

## **3.7 Evaluation Plan**

How will you measure success? Which metrics will you use? Will you compare against baselines? For CS 555 and Paper Track applicants, include planned ablation studies.

*We evaluate along three dimensions. First, citation faithfulness: for each generated finding, a second LLM call judges whether the cited rule actually supports the stated issue (binary score, reported as a rate over 100 test cases). Second, vulnerability detection recall: using the humanevalpack Python split, we measure what fraction of known bugs the system flags and whether the correct bug type is identified. Third, false positive rate: we run the system on 50 clean, well-reviewed Python functions from high-starred GitHub repos and count spurious warnings. All three metrics are also measured for two baselines: (B1) zero-shot local LLM with no retrieval, and (B2) Bandit \+ pylint alone without the LLM layer. We expect our system to outperform B1 on citation faithfulness and B2 on recall, while remaining competitive on false positives.*

## **3.8 Timeline**

Provide a week-by-week plan from now until June 7\. The table below is a suggested structure — fill in each row, or replace it with your own format.

| Week / Dates | Planned Milestones / Deliverables |
| :---- | :---- |
| Week 1 (now – May 10\) | *Finalize dataset collection scripts. Clone Semgrep repos, parse all YAML rules, download CWE XML, collect HuggingFace datasets. Proposal submission.* |
| Week 2 (May 11 – May 17\) | *Build and populate three FAISS indexes from existing datasets. Implement Layer 1 (Bandit \+ pylint integration). Verify chunk quality across all three indexes.* |
| Week 3 (May 18 – May 24\) | *Implement Layer 2 (parallel RAG retrieval) and Layer 3 (prompt builder \+ local LLM). Benchmark Qwen2.5, Llama 3.1, and Mistral on a held-out set and select the best performing model. End-to-end pipeline running. First informal results.* |
| Week 4 (May 25 – May 31\) | *Implement evaluation harness. Run all metrics against both baselines. Error analysis: examine false positives and missed vulnerabilities. Begin Gradio UI.* |
| Week 5 (June 1 – June 7\) | *Final experiments, ablation study (with vs without static analysis layer), report writing, code cleanup, README.* |

## 

## **3.9 Risks and Contingency Plan**

What could go wrong? List 2–3 concrete risks (technical, data-related, compute-related) and your plan B for each.

***Risk 1 — Security index retrieval noise**: With \~2,000 chunks across multiple rule sources, the retriever may return low-relevance results for less common vulnerability patterns, producing hallucinated citations. **Plan B**: Apply a confidence threshold — only include retrieved chunks above a minimum cosine similarity score. Add a re-ranking step using a cross-encoder to filter top-k results further.*

***Risk 2 — Local LLM output quality**: Smaller local models may struggle to consistently produce well-structured JSON with accurate citations. **Plan B**: If no tested model produces reliable structured output, switch to a two-step approach — the local LLM generates free-text findings, then a lightweight parser extracts and formats the structured fields.*

***Risk 3 — Low recall on novel vulnerability patterns**: The system may miss vulnerabilities that do not closely match any indexed rule. **Plan B:** Add a heuristic pass where the LLM reasons freely without retrieval, labeling those findings as ungrounded. Report the two categories separately in the evaluation to maintain honesty.*

## **3.10 Compute Resources**

Which compute will you use? Be honest about your access — this helps validate that the scope is realistic.

* \[X\] Google Colab (free tier)

* \[X\] Kaggle Notebooks

* \[ \] Free credits from Google / other platforms (specify)

* \[ \] Paid APIs — OpenAI / Anthropic / other (cost is your own responsibility)

* \[X\] Local hardware (specify GPU)

* \[ \] Other (specify)

*We plan to use a combination of three compute environments — local machines, Kaggle Notebooks, and Google Colab — and will determine the best fit for each task experimentally as the project progresses rather than committing to a fixed assignment in advance. Local machines will be the first option we try for tasks such as dataset preprocessing, YAML parsing, index building, and running smaller models, as they offer the fastest iteration cycle with no quota constraints. Kaggle Notebooks provide free NVIDIA T4 GPU access with 30 hours of weekly runtime, making them well-suited for embedding generation and running larger local models such as Qwen2.5-7B or Llama 3.1-8B in 4-bit quantization, which fit comfortably within Kaggle's 16 GB GPU memory. Google Colab free tier offers an alternative GPU environment and will be used when Kaggle quota is exhausted or for parallel experimentation. All LLMs used in this project are open-source models running locally — no paid external APIs will be used at any stage. We will benchmark Qwen2.5, Llama 3.1, and Mistral on a small held-out set during Week 3 and continue with whichever produces the most reliable structured output, keeping the final model choice flexible until that evaluation is complete.*

## 

## 

## **3.11 Expected Outcomes**

What do you expect to deliver by June 7? What will the report contain? What will the demo show?

*By June 7 we expect to deliver: (1) a fully runnable Python codebase with a clear README covering environment setup, index building, and running the reviewer on arbitrary Python input; (2) three populated FAISS indexes built entirely from existing public datasets (\~2,000 security chunks, \~300 style chunks, \~1,000 bug pattern chunks); (3) an evaluation report comparing our system against two baselines on citation faithfulness, detection recall, and false positive rate; (4) an error analysis section discussing failure cases honestly, including vulnerability classes the system missed and why; and (5) a short Gradio demo showing the system reviewing real-world vulnerable Python snippets in real time, with color-coded severity output and clickable citations.*

# **Section 4 — References (optional but encouraged)**

List any papers, datasets, or tools you plan to build on. Required for CS 555 and Paper Track applicants.

*\[1\] Lewis et al. (2020). Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks. NeurIPS 2020\.*  
*\[2\] Reimers & Gurevych (2019). Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks. EMNLP 2019\.*  
*\[3\] Johnson et al. FAISS: A library for efficient similarity search. github.com/facebookresearch/faiss*  
*\[4\] Bai et al. (2023). Qwen Technical Report. arxiv.org/abs/2309.16609*  
*\[5\] Meta AI (2024). Llama 3 Model Card. github.com/meta-llama/llama3*  
*\[6\] Dahoas et al. code-review-instruct-critique-revision-python. huggingface.co/datasets/Dahoas*  
*\[7\] Muennighoff. python-bugs dataset. huggingface.co/datasets/Muennighoff/python-bugs*  
*\[8\] BigCode. HumanEvalPack. huggingface.co/datasets/bigcode/humanevalpack*  
*\[9\] Tomo-Melb. CodeReviewQA. huggingface.co/datasets/Tomo-Melb/CodeReviewQA*  
*\[10\] Semgrep community rules repository. github.com/semgrep/semgrep-rules*  
*\[11\] Trail of Bits Semgrep rules. github.com/trailofbits/semgrep-rules*  
*\[12\] semgrep-rules-manager. github.com/iosifache/semgrep-rules-manager*  
*\[13\] MITRE CWE database. cwe.mitre.org/data/*  
*\[14\] OWASP Cheat Sheet Series. github.com/OWASP/CheatSheetSeries*  
*\[15\] Bandit Python security linter. bandit.readthedocs.io*  
