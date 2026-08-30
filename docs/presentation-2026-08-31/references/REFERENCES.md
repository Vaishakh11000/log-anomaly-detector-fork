# References — journal papers only

Every entry below is a **peer-reviewed journal article** from an IEEE Transactions title
or a Web of Science / Scopus indexed journal. No conference papers, no preprint-only
work, no blog posts.

Each one has a freely downloadable **author version** saved in this folder, so the PDFs
travel with the presentation and the panel can read any of them immediately. The author
version is the authors' own copy of the same paper — identical content, different
typesetting from the publisher's copy — and is what the publishers allow authors to
share.

`combined-references.pdf` contains all eight in one file, in the order below.

| # | Paper | Journal | Publisher / index | Year | DOI | Local PDF |
|---|---|---|---|---|---|---|
| R1 | Almodovar, Sabrina, Karimi & Azad — *LogFiT: Log Anomaly Detection Using Fine-Tuned Language Models* | **IEEE Transactions on Network and Service Management**, 21(2), 1715–1723 | IEEE (SCIE / Scopus) | 2024 | [10.1109/TNSM.2024.3358730](https://doi.org/10.1109/TNSM.2024.3358730) | [logfit-tnsm2024.pdf](logfit-tnsm2024.pdf) |
| R2 | Landauer, Onder, Skopik & Wurzenberger — *Deep Learning for Anomaly Detection in Log Data: A Survey* | Machine Learning with Applications, 12, 100470 | Elsevier (Scopus, open access) | 2023 | [10.1016/j.mlwa.2023.100470](https://doi.org/10.1016/j.mlwa.2023.100470) | [dlloganomaly-survey-mlwa2023.pdf](dlloganomaly-survey-mlwa2023.pdf) |
| R3 | Ali, Boufaied, Bianculli, Branco & Briand — *A Comprehensive Study of Machine Learning Techniques for Log-Based Anomaly Detection* | Empirical Software Engineering, 30(5), 129 | Springer (SCIE / Scopus) | 2025 | [10.1007/s10664-025-10669-3](https://doi.org/10.1007/s10664-025-10669-3) | [mlcomparison-emse2025.pdf](mlcomparison-emse2025.pdf) |
| R4 | Wu, Li & Khomh — *On the Effectiveness of Log Representation for Log-Based Anomaly Detection* | Empirical Software Engineering, 28(6), 137 | Springer (SCIE / Scopus) | 2023 | [10.1007/s10664-023-10364-1](https://doi.org/10.1007/s10664-023-10364-1) | [logrepresentation-emse2023.pdf](logrepresentation-emse2023.pdf) |
| R5 | Khan, Shin, Bianculli & Briand — *Impact of Log Parsing on Deep Learning-Based Anomaly Detection* | Empirical Software Engineering, 29(6), 139 | Springer (SCIE / Scopus) | 2024 | [10.1007/s10664-024-10533-w](https://doi.org/10.1007/s10664-024-10533-w) | [logparsing-emse2024.pdf](logparsing-emse2024.pdf) |
| R6 | Pang, Shen, Cao & van den Hengel — *Deep Learning for Anomaly Detection: A Review* | ACM Computing Surveys, 54(2), 1–38 | ACM (SCIE / Scopus) | 2021 | [10.1145/3439950](https://doi.org/10.1145/3439950) | [dlanomaly-csur2021.pdf](dlanomaly-csur2021.pdf) |
| R7 | Kheddar — *Transformers and Large Language Models for Efficient Intrusion Detection Systems: A Comprehensive Survey* | Information Fusion, 124, 103347 | Elsevier (SCIE Q1 / Scopus) | 2025 | [10.1016/j.inffus.2025.103347](https://doi.org/10.1016/j.inffus.2025.103347) | [transformers-ids-inffus2025.pdf](transformers-ids-inffus2025.pdf) |
| R8 | Debicha, Bauwens, Debatty, Dricot, Kenaza & Mees — *TAD: Transfer Learning-Based Multi-Adversarial Detection of Evasion Attacks Against Network Intrusion Detection Systems* | Future Generation Computer Systems, 138, 185–197 | Elsevier (SCIE / Scopus) | 2023 | [10.1016/j.future.2022.08.011](https://doi.org/10.1016/j.future.2022.08.011) | [adversarial-evasion-fgcs2023.pdf](adversarial-evasion-fgcs2023.pdf) |

## Where each paper starts in `combined-references.pdf`

| # | File | Pages | Starts at page |
|---|---|---|---|
| R1 | logfit-tnsm2024.pdf | 9 | 1 |
| R2 | dlloganomaly-survey-mlwa2023.pdf | 21 | 10 |
| R3 | mlcomparison-emse2025.pdf | 68 | 31 |
| R4 | logrepresentation-emse2023.pdf | 43 | 99 |
| R5 | logparsing-emse2024.pdf | 33 | 142 |
| R6 | dlanomaly-csur2021.pdf | 36 | 175 |
| R7 | transformers-ids-inffus2025.pdf | 38 | 211 |
| R8 | adversarial-evasion-fgcs2023.pdf | 16 | 249 |

Total 264 pages.

## Why each one is in the deck

- **R1 LogFiT** — a language model fine-tuned on logs, published in an IEEE Transactions.
  It is the honest replacement for the old "LLM-based log analysis (recent work)" row,
  which cited no actual paper. It is also the closest published work to the approach the
  original proposal described, and it reports its results on clean data only.
- **R2 Landauer et al. survey** — the field-wide survey of deep learning for log anomaly
  detection. Used on the Background slide: it shows what the field measures, and that
  robustness against a deliberately hiding attacker is not part of it.
- **R3 Ali et al.** — compares classical machine learning against deep learning on log
  data and finds simpler models competitive. This is the published support for choosing
  Isolation Forest over a large trained model, instead of it looking like a shortcut.
- **R4 Wu, Li & Khomh** — measures how much the choice of log *representation* (including
  sentence embeddings) matters. Directly supports the embedding step in our pipeline.
- **R5 Khan et al.** — shows how much log parsing quality changes anomaly detection
  results. Supports why we spent effort on the parser, and why our parse rate
  (75.98% → 99.37% on Linux.log) is worth reporting.
- **R6 Pang et al.** — the standard review of deep anomaly detection; supplies the
  definitions and the framing used on the Method slide.
- **R7 Kheddar** — 2025 survey of transformers and LLMs for intrusion detection. Shows
  the field is moving where we are, and that evaluation is still on static datasets.
- **R8 Debicha et al.** — attackers deliberately evading a detector, measured. The single
  closest published work to our adversarial track, and it is on network traffic rather
  than logs, which is exactly the gap we point at.

## The shared limitation these papers reveal

All eight evaluate on data where the attacker is **not trying to hide from the specific
detector being tested**. R8 is the only one with an active adversary, and it targets
network intrusion detection rather than log analysis. None of them compares against a
production SIEM ruleset under camouflage. That absence is our research gap, and it is
citable rather than asserted.

## Verification notes

- Every DOI above was resolved through Crossref, and the title, authors, journal, volume,
  issue, pages and year printed here come from that record rather than from memory.
- Every PDF was downloaded from the authors' own deposit: arXiv for R2–R8, and the
  CQUniversity institutional repository for R1. No paywalled publisher PDF was used.
- Conference papers were deliberately excluded, which is why **DeepLog** (ACM CCS 2017)
  and **LogBERT** (IJCNN 2021) no longer appear in the literature table. If the panel asks
  about them, they are named in the knowledge pack as foundational conference work.

## Rebuilding the combined file

`combined-references.pdf` is 18 MB of the same PDFs already in this folder, so it is not
kept in git. Rebuild it in one command:

```bash
cd docs/presentation-2026-08-31/references
pdfunite logfit-tnsm2024.pdf dlloganomaly-survey-mlwa2023.pdf mlcomparison-emse2025.pdf \
         logrepresentation-emse2023.pdf logparsing-emse2024.pdf dlanomaly-csur2021.pdf \
         transformers-ids-inffus2025.pdf adversarial-evasion-fgcs2023.pdf \
         combined-references.pdf
```
