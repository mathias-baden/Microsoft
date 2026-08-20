# Microsoft Purview Sensitivity Label Downgrade Detection

A KQL query for Microsoft 365 Defender **Advanced Hunting**, paired with a
custom detection rule, that alerts in near real-time when a file's
sensitivity label is downgraded out of a sensitive tier (e.g. HR /
Highly Confidential → Public).

- **Query file:** [`mdca-label-downgrade-query.kql`](./label-downgrade.kql)
- **Data source:** `CloudAppEvents`
- **Detection frequency:** Continuous (NRT)

## How it works

1. A `listLabelNames` function maps each sensitivity label's GUID to a
   human-readable name, so alerts and results show label names instead of
   opaque IDs.
2. The query watches `CloudAppEvents` for four action types that all
   indicate a label was changed or removed.
3. It flags any event where the **source** label is in a monitored
   "sensitive" tier and the **destination** label is not — i.e. a
   downgrade out of that tier.

The label IDs and names in this file are specific to one tenant. **You
must replace them with your own tenant's labels before this query will
return anything meaningful.**

## Step 1 — Get your tenant's label IDs

Sensitivity labels are matched by GUID, not display name, so you need the
underlying IDs first. Easiest way — PowerShell with the Exchange Online
Management module:

```powershell
Connect-IPPSSession -EnableSearchOnlySession
[array]$Labels = Get-Label | Select-Object ImmutableId, DisplayName
$Labels
```

This prints every label in your tenant with its `ImmutableId` (what the
query calls `labelID`) and `DisplayName`. Copy the full output — you'll
need it for step 2.


## Step 2 — Replace the labels in the query

There are three places in the query that reference label IDs, and all
three need to be updated together:

| Location | What it does |
|---|---|
| `let listLabelNames = (labelID: string) { case( ... ) }` | Maps every label ID in your tenant to its display name, for readable output. |
| `where SourceLabel in (...)` | The list of label IDs considered the "sensitive" tier — a downgrade **starts** here. |
| `and DestinationLabel !in (...)` | The same list, reused — a downgrade **ends** somewhere **not** in this list. |

`SourceLabel` and `DestinationLabel` should use the **same** list of IDs
in both places — the query is asking "did this move out of the sensitive
tier," so both sides need to agree on what "the sensitive tier" means.

### Doing this manually

1. Take the `$Labels` output from step 1.
2. In `listLabelNames`, add one `labelID == "<id>", "<name>",` line per
   label — every label you want named in the output, not just the
   sensitive ones (this makes `DestinationLabelName` readable even when
   the destination is something ordinary like *Public*).
3. Decide which of your tenant's labels count as the "sensitive" tier
   (the ones you want to alert on if a file moves *out* of them).
4. Paste that subset's IDs into both the `where SourceLabel in (...)` and
   `!in (...)` lines, as a comma-separated list of quoted strings.

### Doing this with AI

This is a mechanical, repetitive edit — a good fit for handing to an AI
assistant (Claude, Copilot, ChatGPT, etc.) rather than doing by hand.
A prompt that works well:

> Here is a KQL query with a `listLabelNames` function and a
> `SourceLabel in (...)` / `DestinationLabel !in (...)` filter that uses
> placeholder label IDs. Here is my tenant's actual label list from
> `Get-Label` [paste the `$Labels` output]. Update the query to use my
> tenant's IDs and names throughout. Treat these labels as the
> "sensitive" tier for the `where` filter: [list which label *names*
> should count as sensitive, e.g. "HR, Confidential - HR, Highly
> Confidential"]. Leave the rest of the query logic unchanged, and paste
> back the full query.

Paste in the query file's current contents plus your `$Labels` output,
and the assistant can do steps 2–4 above in one pass. Worth doing either
way:

- **Review the output before pasting it into Advanced Hunting.** Confirm
  every ID in `listLabelNames` matches your `Get-Label` output exactly,
  and that the same set of IDs appears in both `in (...)` and `!in (...)`.
- **Paste the AI's output directly from a plain-text editor, not from a
  rendered chat window or Word document.** Copying formatted text can
  introduce invisible characters (smart quotes, non-breaking spaces)
  that look identical on screen but cause `Semantic error: Failed to
  resolve...` in Advanced Hunting. If you hit that error, retype the
  affected line by hand rather than re-pasting it.
- **Keep the label list inline** inside `in (...)` / `!in (...)` rather
  than moving it into a separate `let SensitiveLabels = pack_array(...)`
  variable. It's slightly more to maintain, but a corrupted or dropped
  `let` block is the single most common cause of the "failed to resolve"
  error above — inline avoids the cross-reference entirely.

## Step 3 — Deploy as a custom detection rule

1. In [security.microsoft.com](https://security.microsoft.com), go to
   **Hunting → Advanced Hunting**, paste in the updated query, and run it
   to confirm it returns results (or at least no errors) against your
   tenant.
2. **Save as** → **My queries**.
3. Without navigating away, click **Create custom detection rule**.
4. Fill in name, description, severity, and category.
5. **Frequency:** choose **Continuous (NRT)** — Defender will recommend
   this automatically if the query qualifies.
6. **Impacted entities:** map `AccountId` (User → `AadUserId` →
   `AccountObjectId`) and `Application` (Cloud application → `Name` →
   `Application`). Consider also mapping a File entity to
   `SourceFileName` so the affected document shows up directly in the
   incident view.
7. **Actions:** leave on default unless you want an automated response.
8. Submit to activate.

## Known limitation: NRT and `summarize`

Continuous (NRT) detection rules only support a restricted subset of KQL
operators. If you add a `summarize` step (e.g. to deduplicate events),
the rule can silently stop alerting even though **Run query** in the UI
still returns correct results. If you need deduplication, either:

- Skip it and rely on Microsoft 365 Defender's incident correlation to
  group duplicate telemetry from the same account/file into a single
  incident (works well in practice, since near-real-time detection is
  usually the priority), or
- Switch the rule to a scheduled frequency (e.g. hourly), which supports
  the full KQL operator set including `summarize` — at the cost of no
  longer being near real-time.

## Testing

To confirm the rule works end to end:

1. Create a test document and apply one of your monitored "sensitive"
   labels.
2. Refresh the browser tab so the label change is committed.
3. Change the label to something outside the monitored tier (e.g.
   *Public*).
4. Check **Incidents & alerts** in Microsoft 365 Defender — the alert
   should appear within a couple of minutes.

## License

MIT — adapt freely for your own tenant.