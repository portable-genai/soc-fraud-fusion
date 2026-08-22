# FAQ index

Answers to the questions different teams ask when evaluating, adopting, or reviewing this
repository (G5, the SOC Fraud Fusion Copilot) as a common base for fraud-and-security alert
fusion. Each file is written for a specific audience; skim the one that matches your role.

| FAQ | For | Answers |
|---|---|---|
| [security-faq.md](security-faq.md) | AppSec / security review | server-side identity, the exposure guard, the safety screen around the model, redaction, secrets, supply chain, the anchored audit chain, what is out of scope |
| [portability-faq.md](portability-faq.md) | Architecture / cloud / exit planning | the no-lock-in claim, the three profiles, the executable portability check, sovereign exit, residency, open-format export |
| [features-faq.md](features-faq.md) | Product / SOC / fraud-ops owners | what the copilot produces, what is deterministic vs LLM, how the score is derived, and the full "what this repo owns vs what it integrates" map |
| [adoption-faq.md](adoption-faq.md) | Engineering leads forking the repo | the rename script, upstream fixes, the kernel boundary, retuning bands from pack data, adding a port or a signal type |
| [compliance-faq.md](compliance-faq.md) | Compliance / model risk / privacy | autonomy and maker-checker, PII handling, auditability, the model-risk story, residency enforcement, regulator crosswalk |

These FAQs deliberately do **not** re-document capabilities owned by sibling systems in the
catalog. Where a concern belongs to another repo (the governed knowledge base, the agent registry,
the AI-quality gate, the observability and WORM audit platform, the human-review console), the FAQ
names that system by its catalog id and explains the boundary rather than duplicating it. See
[features-faq.md](features-faq.md) for the full map, and [`../ADOPTING.md`](../ADOPTING.md) for
the fork path.
