# Security Policy

## Authorized Use Only

Vexor is a red team and security research tool. Use it only against systems you own or have **explicit written authorization** to test. Unauthorized use against third-party AI services, APIs, or deployments may violate:

- The Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction
- Provider Terms of Service (OpenAI, Anthropic, Google, Mistral, etc.)
- Applicable data protection and computer misuse regulations

The authors accept no liability for misuse. See [LICENSE](LICENSE).

---

## Responsible Disclosure

If you discover a vulnerability in Vexor itself (e.g., the web UI, API server, or data handling), please report it responsibly:

**Contact:** Open a [GitHub Security Advisory](../../security/advisories/new) (preferred — keeps details private until patched) or email the maintainer directly if you cannot use GitHub.

**Please include:**
- Description of the issue and potential impact
- Steps to reproduce
- Any suggested remediation

We aim to acknowledge reports within **48 hours** and issue a patch or mitigation within **14 days** for confirmed vulnerabilities.

**Please do not** open a public issue for security vulnerabilities before they are patched.

---

## Scope

This policy covers the Vexor application code in this repository. It does **not** cover:

- Third-party AI provider APIs or models (report those directly to the respective vendors)
- Vulnerabilities in models discovered *using* Vexor — those should be reported to the model's vendor via their own responsible disclosure process

---

## Reporting AI Model Vulnerabilities Found With Vexor

If you use Vexor to discover a significant safety or security weakness in a production AI model, please report it to the provider before publishing:

| Provider   | Disclosure contact |
|------------|-------------------|
| Anthropic  | https://www.anthropic.com/security |
| OpenAI     | https://openai.com/security/disclosure |
| Google     | https://bughunters.google.com |
| Meta       | https://www.facebook.com/whitehat |
| Mistral    | security@mistral.ai |

Coordinated disclosure protects users and gives providers time to patch before bypass techniques become public.

---

## API Key and Data Hygiene

Vexor stores scan results locally in `data/scans/` and reads API keys from environment variables or `.env`. Before sharing your Vexor instance or repository fork:

- Ensure `.env`, `data/`, and `configs/model_config.json` (if it contains keys) are in `.gitignore`
- Rotate any API keys that may have been committed or exposed
- Do not expose the Vexor web server (`localhost:7860`) on a public interface without adding authentication
