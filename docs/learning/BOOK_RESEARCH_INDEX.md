# Books and source coverage (source-audited 2026-10-13)

Use this index as a **bibliography plus original interpretation**, not a collection of book contents. Coverage is one of:
- **A:** Author offers a legal complete text publicly; specific chapter sections were actually consulted.
- **B:** Official excerpt and/or author curriculum read.
- **C:** Publisher/catalog summary and/or contents inspected, not full text.
- **D:** Adjacent book not confirmed on the photographed shelf; for optional reference.

| Work | Level | Source | What is taught | Distinct Pulpo/finance learning |
|---|---|---|---|---|
| Al Sweigart, *Automate the Boring Stuff with Python* (3e) | A; actual selected chapters | [Full author-published text](https://automatetheboringstuff.com/3e) | Python, CLI, files, CSV/JSON, SQLite, web, email, UI | Format validation is not capability custody; see chapter-specific audit below |
| Haley Sacks, *Future Rich Person* | C | [Publisher](https://www.penguinrandomhouse.com/books/787317/future-rich-person-by-haley-sacks/) | Money organization, budgeting, earning, reserves, investing | A rule must identify priority, not just allocate money |
| Jean Chatzky, *The Forever Paycheck* | C | [Publisher](https://www.penguinrandomhouse.com/books/805286/the-forever-paycheck-by-jean-chatzky/) | Converting retirement assets into regular income | Distinguish liquid stock from ongoing obligations and income |
| Ramit Sethi, *I Will Teach You to Be Rich* | C | [Library of Congress chapters](https://catdir.loc.gov/catdir/enhancements/fy1005/2008056014-t.html) | Credit, banking, investing, conscious spending and automation | Defaults must be bounded by independently approved thresholds |
| Dave Ramsey, *The Total Money Makeover* | C | [Official Seven Baby Steps](https://www.ramseysolutions.com/dave-ramsey-7-baby-steps) | Starter reserves, debt snowball, full reserves, later investment | Debt snowball is behavioral; compare with interest-minimizing avalanche |
| Carrie Joy Grimes, *The Joy of Money* | B | [Author's ten money levels](https://thejoyofmoney.com/) | Stepwise budget, emergency fund, debt, benefits, investment | Define completion gates per level; no universal money score |
| Vivian Tu, *Well Endowed* | C | [Publisher](https://www.harpercollins.com/pages/wellendowed) | Family financial decisions, insurance, home/car, legacy | Treat lifecycle/legal decisions as external, separately authorized |
| Anne Lester, *Your Best Financial Life* | C | [Library catalog TOC](https://catalog.freelibrary.org/Record/2685499) | Compounding, emergency fund, tax-advantaged saving, diversified investing | Model objectives with explicit assumptions and uncertainty |
| Robert Kiyosaki, *Rich Dad Poor Dad* | C | [Critical review](https://www.investmentnews.com/guides/rich-dad-poor-dad-in-the-context-of-modern-financial-advice/263252) | Ownership and cash-flow intuitions | Do not equate popular 'asset' metaphor with accepted accounting definitions |
| Tiffany Aliche, *Get Good with Money* | B | [Publisher excerpt](https://www.penguinrandomhouse.com/articles/get-good-with-money-excerpt/) | Ten-part financial wholeness (budget, saving, debt, credit, earnings, etc.) | A bank balance alone does not prove household or company solvency |
| Tori Dunlap, *Financial Feminist* | C | [Author overview](https://herfirst100k.com/financial-feminist-book) | Money psychology, spending, earning, debt and investing | Include income leverage and negotiation, not only expense cuts |
| *Credit Repair Kit for Dummies* | C | [Library chapter inventory](https://catalog.freelibrary.org/Record/2562524) | Credit report accuracy, disputes, monitoring and recovery | Separate observed error from unverified dispute outcome |
| Allison Baum Gates, *Breaking into Venture* | C | [O'Reilly listing](https://www.oreilly.com/library/view/breaking-into-venture/9781264702688/) | Sourcing and evaluating investment opportunities | A company valuation is not operational cash; distinguish investor claim from proof |
| Ilysse Ratner, *Cash Stash: Tight Budgets* | C | [Publisher](https://www.sourcebooks.com/9798886087239-cash-stash-activity-book-tight-budgets-tp.html) | Savings habits through small challenges | Small budgets benefit from pacing, not impossible commitments |
| Ramit Sethi, *Money for Couples* | D | [Author](https://www.iwillteachyoutoberich.com/money-for-couples/) | Joint financial goals and routines | Joint agreement does not imply blanket financial authority |
| Vivian Tu, *Rich AF* | D | [Publisher](https://www.penguinrandomhouse.com/books/735755/rich-af-by-vivian-tu/) | Financial literacy and money habits | Compare financial language with precise ledger semantics |
| Morgan Housel, *The Psychology of Money* | D | [Publisher](https://www.simonandschuster.com/books/The-Psychology-of-Money/Morgan-Housel/9780857197689) | Incentives, luck/risk, staying wealthy | Decision rules require margin of safety and revision boundaries |
| Thomas Stanley and William Danko, *The Millionaire Next Door* | D | [Publisher](https://www.simonandschuster.com/books/The-Millionaire-Next-Door/Thomas-J-Stanley/9781630762506) | Wealth accumulation versus conspicuous consumption | Distinguish observable income from unobserved net worth |

## Actual selectively read Automate, 3e chapter map

Source: https://automatetheboringstuff.com/3e

| Chapters reviewed | Findings useful for safe labs |
|---|---|
| 1, 5 | Types, exceptions, logging, debugging and assertion checks; fail on malformed inputs |
| 10-12 | Explicit paths and filesystem changes; command-line contracts; dry-run and idempotency |
| 13-15 | Web scraping, spreadsheet inputs, source provenance, third-party permissions |
| 16 | SQLite database keys/queries; SQLite has no built-in separate DB user roles and weak column affinity by default: persistence does **not** prove isolation |
| 17-18 | PDFs can have difficult extraction; CSV string-only fields, correct CSV quoting and safe JSON parsing; hash precise bytes |
| 19-20 | Schedules and notification senders are external effect routes; separate accounts, dry runs, scoped authorization |
| 23-24 | OS accessibility can enable broad GUI control; audio/voice input is untrusted data, not privileged authority |

**Further instruction:** The author text is available online, but this index does not assert full line-by-line reading. Copyrighted publisher chapters and books not user-provided are **not** mirrored.

## Cross-book conclusions and limits

1. Debt repayment optimization depends on whether the objective is psychological progress, interest cost, liquidity or credit improvement. There is no universally best algorithm.
2. Keep *household emergency reserve*, *corporate operating cash* and *equity valuation* in different ledgers/analyses.
3. Never infer consent or execution authorization from a book recommendation or AI-generated plan.
4. An expense ledger's recorded amount may be wrong or stale. Reconciliation needs evidence of actual payment, beneficiary, recurring terms and timing.
5. Use source-labeled, revisable knowledge notes with citation, edition, confidence and counterexamples; do not silently make learning an authority expansion.

Continue at [README](README.md) and [Lesson 01](LESSON_01_RELIABLE_DATA.md).
