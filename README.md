# Secure Software Development: Static Source Code Vulnerability Scanner

A Python-based static application security testing (SAST) tool designed to scan source code files for common vulnerabilities and unsafe functions. Developed as part of a secure software development lab simulating a manufacturing facility security audit.

---

## 🛠️ Project Overview

In industrial and manufacturing environments, software controlling production equipment must adhere to strict security standards to prevent operational disruption, system compromise, or safety hazards. This tool acts as a lightweight static code analyzer (`static_final.py`), parsing source code files to automatically flag risky constructs and insecure function calls.

---

## 🚀 Key Features

* **Automated Source Code Parsing:** Reads and analyzes target script files line-by-line or via Abstract Syntax Tree (AST) patterns.
* **Vulnerability Pattern Matching:** Identifies known high-risk functions, dangerous imports, and insecure coding anti-patterns.
* **Detailed Reporting:** Generates clear, actionable findings highlighting vulnerability types, locations, and risk levels.
* **Modular Design:** Easily extensible to include custom signature rules and regex-based detection patterns.

---

## 📋 Implementation Steps

1. **Plan & Set Up Environment:** Initialized development using VS Code, transitioning from the starter template (`static_starter.py`) to the finalized scanner implementation (`static_final.py`).
2. **Collect Source Code:** Configured the tool to ingest target python source files for inspection.
3. **Parse the Code:** Implemented robust file reading and string/token parsing mechanisms.
4. **Define Vulnerability Patterns:** Established signature rules targeting common security pitfalls (e.g., dangerous execution sinks, hardcoded secrets, or unsafe module imports).
5. **Implement Analysis Logic:** Built scanning loops to evaluate parsed code against defined security rules.
6. **Generate Findings Report:** Outputted formatted results summarizing identified vulnerabilities for remediation.

---

## 💻 Usage

To run the vulnerability scanner on a target script, execute the following command in your terminal:

```bash
python static_final.py --target <path_to_source_file.py>
