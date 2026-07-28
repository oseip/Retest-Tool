# 10. Duplicate Detection

Finds duplicate Jira tickets that report the same finding on the same asset — **all statuses** (including Fixed, Closed, and Done).

**Grouping key:** IP + summary + port for **IPT / SCN / EPT** (and legacy scan tickets with a port but no TestType). All other TestTypes also include **Affected System**.

• Highlights the **oldest ticket** as the recommended one to keep.

• Shows tester info extracted from the OtherInformation field.

• Export results as an Excel (`.xlsx`) file for cleanup workflows.

Select a client and click **Find Duplicates** to scan the entire project backlog.

![Duplicate Detection](../feature_guide_assets/08_duplicates_annotated.png)

*Screenshot: Duplicate Detection (annotated)*


---

[← 9. Weekly Report](../features/weekly-report.md) · [11. Batch Scan →](../features/batch-scan.md)

