---
base_model:
- fdtn-ai/Foundation-Sec-8B
language:
- en
library_name: transformers
license: other
pipeline_tag: text-generation
tags:
- security
- llama
---

# Foundation-Sec-8B-Instruct - Model Card

## Model Information

Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct (Foundation-Sec-8B-Instruct) is an open-weight, 8-billion parameter instruction-tuned language model specialized for cybersecurity applications. 
It extends the Foundation-Sec-8B base model with instruction-following capabilities.
It leverages prior training to understand security concepts, terminology, and practices across multiple security domains.
Further instruction-tuning allows the model to interact with human users in a chat-like interface.
Foundation-Sec-8B-Instruct enables organizations to build AI-driven security tools that can be deployed locally, reducing dependency on cloud-based AI services while maintaining high performance on security-related tasks.

- **Model Name:** Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct (Foundation-Sec-8B-Instruct)
- **Model Developer:** Foundation AI at Cisco
- **Model Card Contact:** https://fdtn.ai/contact
- **Technical Report:** [Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct Technical Report](https://huggingface.co/papers/2508.01059)
- **Model Release Date:** August 1st, 2025
- **Supported Language(s):** English
- **Model Architecture:** Auto-regressive language model that uses an optimized transformer architecture (Meta Llama-3.1-8B backbone)
- **Training Objective:** Instruction following and alignment with human preferences
- **Training Data Status:** This is a static model trained on an offline dataset. Future versions of the tuned models will be released on updated data.
- **License:** See NOTICE.md
    

## Intended Use

### Intended Use Cases

Foundation-Sec-8B-Instruct is designed for security practitioners, researchers, and developers building AI-powered security workflows and applications. 
Foundation-Sec-8B-Instruct is optimized for three core use case categories:

- **SOC Acceleration**: Automating triage, summarization, case note generation, and evidence collection.
- **Proactive Threat Defense**: Simulating attacks, prioritizing vulnerabilities, mapping TTPs, and modeling attacker behavior.
- **Engineering Enablement**: Providing security assistance, validating configurations, assessing compliance evidence, and improving security posture.

The model is intended for local deployment in environments prioritizing data security, regulatory compliance, and operational control.

### Downstream Use

Foundation-Sec-8B-Instruct can be used directly for security-related chat use cases. Example downstream applications include:

- Summarization
    - Summarizing detection playbooks and incident reports
    - Consolidating fragmented analyst notes into structured case summaries
- Classification
    - Mapping threats to MITRE ATT&CK techniques
    - Prioritizing vulnerabilities based on contextual risk
    - Classifying security-relevant emails and leaked file contents
- Named Entity Recognition
    - Extracting compliance evidence from documents
    - Building network behavior profiles from technical manuals
- Question & Answer
    - Assisting SOC analysts with alert triage and investigation
    - Responding to cloud security and software compliance queries
- Reasoning and Text Generation
    - Generating red-team attack plans and threat models
    - Predicting attacker next steps in active investigations
    - Enriching vulnerability scan results with contextual insights

For questions or assistance with fine-tuning Foundation-Sec-8B-Instruct, please reach out to the team. 

### Out-of-Scope Use

The following uses are out-of-scope and are neither recommended nor intended use cases:

1.  **Generating harmful content** - The model should not be used to:
    -   Generate malware or other malicious code
    -   Create phishing content or social engineering scripts
    -   Develop attack plans targeting specific organizations
    -   Design exploitation techniques for vulnerabilities without legitimate security research purposes
2.  **Critical security decisions without human oversight** - The model should not be used for:
    -   Autonomous security decision-making without human review
    -   Critical infrastructure protection without expert supervision
    -   Final determination of security compliance without human verification
    -   Autonomous vulnerability remediation without testing
3.  **Legal or medical advice** - The model is not qualified to provide:
    -   Legal advice regarding security regulations, compliance requirements, or intellectual property disputes
    -   Legal advice regarding security issues that would reference legal statutes, precedents, or case law necessary to provide legal advice
    -   Medical advice regarding health impacts of security incidents
4.  **Non-security use cases** - The model is specifically optimized for cybersecurity and may not perform as well on general tasks as models trained for broader applications.
5.  **Violation of Laws or Regulations** - Any use that violates applicable laws or regulations.

## How to Get Started with the Model

Use the code below to get started with the model.
[The cookbook](https://github.com/cisco-foundation-ai/cookbook) provides example use cases, code samples for adoption, and references.

```python
# Import the required libraries
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

# Load the model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("fdtn-ai/Foundation-Sec-8B-Instruct")
model = AutoModelForCausalLM.from_pretrained("fdtn-ai/Foundation-Sec-8B-Instruct")

prompt = "CVE-2015-10011 is a vulnerability about OpenDNS OpenResolve improper log output neutralization. What is the corresponding CWE?"

messages = [
    {"role": "user", "content": prompt}
]

model_inputs = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
inputs = tokenizer(model_inputs, return_tensors="pt", add_special_tokens=False)
output = model.generate(**inputs, temperature=0.1, max_new_tokens=250)
resp = tokenizer.batch_decode(output)[0]
print(resp.replace(model_inputs, ""))
```

## Training and Evaluation

### Training Data

Foundation-Sec-8B-Instruct was trained on a wide variety of public and proprietary question answer/pairs for general and security-specific instruction-following.

**Data cutoff:** April 10th, 2025.

A more detailed description of the methodology is available in the technical report. 

### Training Setup

Foundation-Sec-8B-Instruct is based on the **Llama 3.1 8B** architecture. Training was performed on Cisco Foundation AI’s internal compute cluster.

Key training details:

- **Instruction fine-tuning** to follow human instructions
- **RLHF** to align model answers to human preferences
- **4096-token** sequence length
- **Optimizer:** AdamW

A more detailed description of the methodology is available in the technical report. 

### Evaluation

Foundation-Sec-8B-Instruct was benchmarked on cybersecurity and general reasoning tasks, using a standardized 0-shot instruction prompting setup (temperature = 0.3).

| **Benchmark** | **Foundation-sec-8B** | **Llama 3.1 8B** | **GPT-4o-mini** |
| --- | --- | --- | --- |
| CTI-MCQA | 0.644 | 0.617 | 0.672 |
| CTI-RCM | 0.692 | 0.558 | 0.655 |
| CTI-VSP | 0.802 | 0.815 | 0.792 |
| IF-Eval | 0.811 | 0.791 | 0.834 |
| Alpaca Eval 2 | 35.453 | 24.477 | 52.720 |

**Benchmark Overview:**

- **CTI-MCQA:** 2,500 multiple-choice questions testing cybersecurity knowledge across frameworks like MITRE ATT&CK, NIST, GDPR, and threat intelligence best practices.
- **CTI-RCM:** 1,000 vulnerability root cause mapping examples linking CVEs to CWE categories, assessing deep understanding of security weaknesses.
- **CTI-VSP:** A set of 1,000 CVE descriptions where models predict the CVSS v3 Base metrics and compute the overall score, with performance measured by the average absolute difference from the true scores.
- **IF-Eval:** 541 instruction-following prompts designed for automated, reproducible assessment of LLM instruction-following capabilities.
- **Alpaca Eval 2:** 805 single-turn prompts auto-scored by GPT-4 Turbo against a GPT-4 Turbo reference, validated with 20,000 human preference votes, and closely matching ChatBot Arena results.  

**Key highlights:**

- **+3 to +11 point gains** over Llama-3.1-8B-Instruct across security-specific benchmarks.
- **Exceptional Instruction-Following capabilities** exceeding that of Llama-3.1-8B-Instruct.
- **Competitive against small Frontier Models** such as GPT-4o-mini on instruction-following capabilities and cybersecurity tasks.

For full benchmark details and evaluation methodology, please refer to the technical report. 

## Safety Alignment

Standard best practices were followed to align the model with general safety values.
Despite the alignment, however, safe out-of-the-box performance cannot be guaranteed.
Our evaluations show that while the model can achieve reasonable safety performance out-of-the-box, LlamaGuard provides much better protection against malicious requests.
It is recommended to deploy this model with additional safeguards (such as LlamaGuard) and human oversight.

| Model                  | HarmBench Performance |
|---|---|
| Llama-3.1-8b-Instruct      | 72.43%                |
| Foundation-Sec-8B-Instruct                 | 91.98%                |
| **LlamaGuard** + Foundation-Sec-8B-Instruct    | 99.25%                |


## Limitations

Foundation-Sec-8B-Instruct has several limitations that users should be aware of:

1.  **Domain-specific knowledge limitations**:
    -   Foundation-Sec-8B-Instruct may not be familiar with recent vulnerabilities, exploits, or novel attack vectors or security technologies released after its training cutoff date
    -   Knowledge of specialized or proprietary security systems or tools may be limited
2.  **Potential biases**:
    -   The model may reflect biases present in security literature and documentation
    -   The model may be trained on known attack patterns and have difficulty recognizing novel attack vectors
    -   Security practices and recommendations may be biased toward certain technological ecosystems
    -   Geographic and cultural biases in security approaches may be present
3.  **Security risks**:
    -   The model cannot verify the identity or intentions of users
    -   Adversarial prompting techniques might potentially bypass safety mechanisms
    -   The model may unintentionally provide information that could be misused if proper prompting guardrails are not implemented
4.  **Contextual blindness:**
    -   The model may struggle to understand the complex interrelationships between systems, users, and data in order to provide accurate context.
5.  **Technical limitations**:
    -   Performance varies based on how security concepts are described in prompts
    -   May not fully understand complex, multi-step security scenarios without clear explanation
    -   Cannot access external systems or actively scan environments
    -   Cannot independently verify factual accuracy of its outputs
6.  **Ethical considerations**:
    -   Dual-use nature of security knowledge requires careful consideration of appropriate use cases
    

### Recommendations

To address the limitations of Foundation-Sec-8B-Instruct, we recommend:

1.  **Human oversight**:
    -   Always have qualified security professionals review model outputs before implementation
    -   Use the model as an assistive tool rather than a replacement for expert human judgment
    -   Implement a human-in-the-loop approach for security-critical applications
2.  **System design safeguards**:
    -   Implement additional validation layers for applications built with this model
    -   Consider architectural constraints that limit the model's ability to perform potentially harmful actions (excessive agency)
    -   Deploy the model in environments with appropriate access controls
3.  **Prompt engineering**:
    -   Use carefully designed prompts that encourage ethical security practices
    -   Include explicit instructions regarding responsible disclosure and ethical hacking principles
    -   Structure interactions to minimize the risk of inadvertently harmful outputs
4.  **Knowledge supplementation**:
    -   Supplement the model with up-to-date security feeds and databases
    -   Implement retrieval-augmented generation for current threat intelligence sources
5.  **Usage policies**:
    -   Develop and enforce clear acceptable use policies for applications using this model
    -   Implement monitoring and auditing for high-risk applications
    -   Create documentation for end users about the model's limitations