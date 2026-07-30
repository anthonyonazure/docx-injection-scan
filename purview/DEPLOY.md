# Deploying the injection detection rule to a Microsoft 365 tenant

Nothing here has been deployed. Every step below changes a live tenant, so it is
written for you to run deliberately, in simulation mode first.

## What this rule can and cannot see

Purview inspects the **extracted text** of a file. That has one happy consequence
and one hard limit.

The happy one: invisible text is still text. A white-on-white payload is fully
visible to Purview even though a human sees nothing. You do not need Purview to
understand formatting in order to catch the payload's words.

The hard limit: Purview cannot tell you the text *was* invisible. It has no idea
whether a phrase was 1pt white or 12pt black. So the invisibility itself, the one
signal an attacker cannot fake away, is unavailable at this layer. That signal
only exists in the pre-upload scanner in the parent folder.

Read that as a division of labour, not a redundancy. The scanner catches hidden
text regardless of language or wording. Purview catches known wording regardless
of where the file came from. Neither covers the other's blind spot.

## Step 1: upload the rule package

Security & Compliance PowerShell. **Open a fresh terminal window for this.** The
Exchange, Teams, and Graph modules each ship their own MSAL library and collide
with assembly error 0x80131040 when loaded together, so run one Microsoft module
per window.

```powershell
Connect-IPPSSession -UserPrincipalName admin@yourtenant.onmicrosoft.com

New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes("C:\path\to\ai-injection-sit.xml"))

Get-DlpSensitiveInformationType | Where-Object Name -like "AI Prompt*"
```

To update it later, bump `<Version>` in the XML and use
`Set-DlpSensitiveInformationTypeRulePackage` with the same command shape.

If the upload rejects the file encoding, re-save the XML as UTF-16 LE and retry.

## Step 2: test the rule before it touches a policy

In the Purview portal, open the sensitive info type and use **Test**. Feed it the
generated test documents from `../testdocs/`. Expected results:

| Test document | Should match | Why |
| --- | --- | --- |
| `01-white-text-en.docx` | yes, 85 | override phrasing plus AI nouns |
| `02-foreign-french.docx` | yes | French override branch |
| `03-foreign-chinese.docx` | yes | Chinese override branch |
| `04-foreign-russian.docx` | yes | Russian override branch |
| `05-homoglyph.docx` | **no** | Purview does not fold lookalike letters, see the gap below |
| `14-no-keywords.docx` | **no** | payload deliberately contains no injection wording |
| `00-clean.docx` | no | control |

Two of those are expected misses, and they are the honest measure of this layer.
Homoglyph substitution and plain-prose payloads defeat keyword matching by
design. The scanner catches both on formatting. Do not tune the regex to chase
them; you will only add false positives.

## Step 3: the DLP policy

Create one policy, two rules.

**Rule A, content match.** Condition: content contains the sensitive info type
*AI Prompt Injection Indicators*, confidence 75 and above. Locations: SharePoint,
OneDrive, Exchange, Teams. Action: for the first two weeks set **simulation mode**
with alerts only. Read what it catches. Then move to block or quarantine once you
know the false positive rate in your own document set.

Start at 75, not 65. Confidence 65 patterns will match ordinary documents about AI
(your own proposals, vendor material, this very file), and an alert channel people
stop reading is worse than no alert.

**Rule B, uninspectable files.** Condition: the document could not be scanned, or
is password protected. Action: block, or route for review. This closes the
simplest bypass of the entire content-inspection approach, which is to encrypt the
file so there is no text to inspect. Without this rule, an attacker skips every
control above by setting a password and putting it in the filename.

## Step 4: reduce what a successful injection can reach

Content inspection is a filter, never a wall. These reduce the payoff.

**Restricted SharePoint Search** limits Copilot's tenant-wide grounding to an
approved list of sites while you fix permission sprawl. This is the highest-value
control in the list, because most real Copilot incidents are oversharing, not
injection.

**Sensitivity labels that remove EXTRACT rights** stop Copilot from summarising
the labelled content at all. Useful for your most sensitive material.

**Purview audit and DSPM for AI** record Copilot interactions. This is where you
would see an injection that got through, so make sure someone actually looks.

## What you cannot do

There is no supported hook into Copilot's own retrieval pipeline. Microsoft does
not expose a pre-grounding inspection point to customers. Everything above works
by gating what reaches a location Copilot reads. A document arriving through an
ungated path, a personal OneDrive, a Teams chat, an external share, a link the
model fetches, is not covered by any of it.
