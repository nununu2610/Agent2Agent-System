# A2A-MIS: Malware Intelligence System (Analyst + Auditor)

## Overview

This repository implements a **multi-agent** chatbot system for automated malware analysis and incident response (IR) advising. The system focuses on providing high-fidelity technical reports while ensuring compliance with organizational security policies.

The system works in two stages:

1. **AnalystAgent**: Provides a fast technical summary of the target malware using web search (**OSINT**) for up-to-date threat intelligence and behavioral data.
2. **AuditorAgent**: Retrieves internal security protocols from a **vector store** (RAG), then validates and refines the report using a **reflection loop** to ensure the response adheres to internal IR standards (e.g., mandatory network isolation).

---

## Install & Running the System

### 1. Install dependencies

**Requires:** Python 3.10+ (recommended Python 3.12).

**Run:**

```bash
pip install -r requirements.txt
