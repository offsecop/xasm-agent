
Assumptions:
- All targets are online and testable and the tools should work against them.
- There's no connectivity issue between the test agents and the targets.

## 🎉 IMPORTANT: NULL Pool Assignment Issue RESOLVED (2025-11-11)

**CRITICAL FIX:** The chronic NULL agent pool assignment issue has been fully resolved!

**What was fixed:**
- ✅ Workflow edits no longer erase pool assignments
- ✅ Workflow duplicates now preserve pool assignments
- ✅ Test 1, 2, and 3 all have pools assigned

**What this means for testing:**
- ✅ All test workflows now have pool assignments by default
- ✅ No need to manually fix NULL pools before running tests
- ✅ Editing workflows during tests won't break them
- ✅ execute-workflow-tests.js should run without pool-related issues

**For details, see:** `CHANGELOG.md` - "CRITICAL: NULL Agent Pool Assignment - Chronic Issue RESOLVED"

**Migration status:** All existing workflows (Test 1, 2, 3) have been migrated and verified with pool assignments.

---

## Test Execution Script

### Overview

The `execute-workflow-tests.js` script automates the execution of all three workflow tests sequentially with comprehensive cleanup, verification, and reporting.

**Location:** `/Users/mvpenha/code/asm-platform/execute-workflow-tests.js`

**Usage:**
```bash
cd /Users/mvpenha/code/asm-platform
node execute-workflow-tests.js
```

**Output:** Test execution logs are written to console and optionally to `test-execution-final.log` using `tee`.

### Features

1. **Pre-Flight Validation**
   - Verifies Production Scanner Pool exists and has healthy agents
   - Checks that all three test workflows exist
   - Validates system health (backend responding, Docker containers stable)

2. **Comprehensive Cleanup**
   - **Pre-Cleanup Verification:** Checks existing data before cleanup
   - **Asset Cleanup:** Deletes services, web endpoints, and findings for target assets
   - **Stuck Execution Cancellation:** Cancels any RUNNING/PENDING workflow executions
   - **Job Cancellation:** Cancels all PENDING/RUNNING jobs
   - **Post-Cleanup Verification:** Verifies cleanup completed successfully
   - **Retry Logic:** If cleanup incomplete, retries individual deletion

3. **Test Execution**
   - Executes workflows sequentially (Test 1 → Test 2 → Test 3)
   - Monitors execution progress with 30-second polling
   - 20-minute timeout per test
   - Real-time step progress reporting

4. **Success Criteria Verification**
   - Validates all success criteria for each test
   - Checks data creation (services, endpoints, findings)
   - Verifies workflow completion status
   - Reports pass/fail for each criterion

5. **Final Reporting**
   - Summary of all test results
   - Total execution time
   - Pass/fail status for each test
   - Criteria met vs. total criteria

### Cleanup Details

The script performs thorough cleanup before each test:

**For Test 1 (testphp.vulnweb.com):**
- Cleans up both FQDN (`testphp.vulnweb.com`) and IP (`44.228.249.3`) assets
- Deletes services, web endpoints, and findings
- Verifies zero findings remain (throws error if findings still exist)

**For Test 2 & 3 (scanme.nmap.org):**
- Cleans up both FQDN (`scanme.nmap.org`) and IP (`45.33.32.156`) assets
- Deletes services, web endpoints, and findings
- Warns if data remains but continues (less strict than Test 1)

**Cleanup Methods:**
- **Services:** Individual deletion via `/api/services/{id}`
- **Web Endpoints:** Bulk delete via `/api/web-endpoints/by-asset/{assetId}` with fallback to individual deletion
- **Findings:** Bulk delete via `/api/findings?assetId={assetId}` with fallback to individual deletion for directly linked findings
- **Executions:** Cancel via `/api/workflows/executions/{id}/cancel`
- **Jobs:** Cancel via `/api/jobs/{id}/cancel` (PATCH)

### Verification Logic

The script uses `verifyAssetData()` function to check:
- **Services:** Counts services linked to asset via `assetId`
- **Web Endpoints:** Counts endpoints linked via `service.assetId`, `assetId`, or `asset.id`
- **Findings:** Counts findings linked via `resourceId`, `assetId`, or `resource.id`

Handles multiple API response structures (array vs object for `affectedResources`).

### Configuration

**API Endpoint:** `http://localhost:3001/api`
**Credentials:** `admin@test.com` / `admin`
**Timeout:** 20 minutes per test (1200 seconds)
**Polling Interval:** 5 seconds for execution monitoring

### Known Issues & Limitations

1. **Web Endpoints API Bug:** API returns `url: undefined` - data exists in database but UI cannot display correctly
2. **Auto-Tagging:** Port 80 may not receive `web_application` tag consistently
3. **Test 1 Katana Failure:** Katana step may fail without clear error message (needs investigation)
4. **Workflow Status Bug:** Test 3 showed all steps COMPLETED but execution marked FAILED (from previous runs)

### Customization

To modify the script:
- **Change targets:** Edit asset values in `executeTest1()`, `executeTest2()`, `executeTest3()`
- **Adjust timeouts:** Modify `monitorExecution()` timeout (default 1200s)
- **Add tests:** Create new `executeTestN()` function following existing pattern
- **Modify criteria:** Update `verifyTest1Success()`, `verifyTest2Success()`, `verifyTest3Success()`

### Troubleshooting

**If cleanup fails:**
- Check API connectivity: `curl http://localhost:3001/api/health`
- Verify authentication: Check credentials in script
- Check asset IDs: Verify assets exist via `/api/assets`
- Review logs: Check backend logs for deletion errors

**If tests fail:**
- Check agent pool health: Verify agents are ONLINE
- Check job status: Review `/api/jobs` for stuck jobs
- Check execution details: Review `/api/workflows/executions/{id}`
- Review backend logs: Check for errors during workflow execution

### Example Output

```
╔════════════════════════════════════════════════════════════════════════════╗
║         SEQUENTIAL WORKFLOW TEST EXECUTION - Tests 1, 2, 3                ║
╚════════════════════════════════════════════════════════════════════════════╝

[11:57:06] [SUCCESS] ✅ Authentication successful

================================================================================
PRE-FLIGHT SYSTEM VALIDATION
================================================================================

[11:57:06] [SUCCESS] ✅ Found pool: Production Scanner Pool
[11:57:06] [SUCCESS] ✅ 5/5 agents are healthy
[11:57:06] [SUCCESS] ✅ Test 1: Test 1: Katana → Nuclei (testphp)
[11:57:06] [SUCCESS] ✅ Test 2: Test 2: Nmap → Katana (scanme)
[11:57:06] [SUCCESS] ✅ Test 3: Test 3: Nmap → Katana → Nuclei (scanme)

================================================================================
TEST 1: KATANA → NUCLEI (testphp.vulnweb.com)
================================================================================

[11:57:12] [SUCCESS] ✅ Cleanup verified - proceeding with test
[11:57:12] [SUCCESS] ✅ Workflow started - Execution ID: 20a634af...
[12:07:13] [ERROR] ❌ Execution FAILED after 600s

================================================================================
FINAL TEST SUMMARY
================================================================================

Total execution time: 1969s (32min 49s)
Test 1: ❌ FAILED (600s)
Test 2: ✅ PASSED (570s) - 4/5 success criteria met
Test 3: ✅ PASSED (762s) - 5/6 success criteria met
```

---

## Test 1: Katana → Nuclei

  - Name: Test 1: Katana → Nuclei
  - Agent Assignment: Pool → "Production Scanner Pool"
  - Step 1: katana:crawl, target: http://testphp.vulnweb.com
  - Step 2: nuclei:info_scan, targets: {{json step1.output.urls}}

**Pre-requisites:**
1. The enumerated web endpoints for the asset testphp.vulnweb.com must be cleaned up before the workflows execution so that we can properly test the web endpoint enumeration via Katana crawling.
2. The security findings for the asset testphp.vulnweb.com or its IP (44.228.249.3) must be cleaned up before the workflow execution so that we can properly test the security scan from nuclei
3. All the current running jobs must be killed
4. The agents from the Production Scanner Pool must be validated to understand if they have any stuck job or process
5. The backend/frontend should be restarted after all changes/fixes to see if compiling or other errors will happen
6. If the test is successful at the end, changes must be committed to git
7. Fixes/changes/improvements will be documented in the changelog.md

**Success criteria:**
1. The web endpoints for the asset testphp.vulnweb.com (44.228.249.3) will be enumerated katana crawling and shown on the UI
2. The output urls identified by Katana will be injected/sent to nuclei as targets (list)
3. Nuclei will be able to scan all the targets (web endpoints) previously identified by Katana using the info scan (severity -s)
4. All the objects will be shown in the asset graph with their correct relationship asset, ports/services, web endpoints
5. The workflow will be marked as completed and show on the UI under Workflows > executions

----------------------------------------------------------------------------------------------------

## Test 2: Nmap → Katana

  - Name: Test 2: Nmap → Katana
  - Agent Assignment: Pool → "Production Scanner Pool"
  - Step 1: nmap:quick_scan, target: scanme.nmap.org
  - Step 2: katana:crawl, url: http://scanme.nmap.org

**Pre-requisites:**
1. The services for the asset scanme.nmap.org must be cleaned up before the workflows execution so that we can properly test the service enumeration via NMAP Scan.
2. The enumerated web endpoints for the asset scanme.nmap.org must be cleaned up before the workflows execution so that we can properly test the web endpoint enumeration via Katana crawling.
3. The security findings for the asset scanme.nmap.org must be cleaned up before the workflow execution so that we can properly test the security scan from nuclei
4. All the current running jobs must be killed
5. The agents from the Production Scanner Pool must be validated to understand if they have any stuck job or process
6. The backend/frontend should be restarted after all changes/fixes to see if compiling or other errors will happen
7. If the test is successful at the end, changes must be committed to git

**Success criteria:**
1. The services for the asset scanme.nmap.org will be enumerated via the nmap scan, including the tcp port 80, and they will be visible on the UI
2. tcp port 80 will be recognized as http during the nmap service scan, therefore, auto-tagged as web_application via our system auto-tagging feature
3. katana will be able to crawl the web endpoints from the asset scanme.nmap.org and they will be visible on UI
4. All the objects will be shown in the asset graph with their correct relationship asset, ports/services, web endpoints
5. The workflow will be marked as completed and show on the UI under Workflows > executions

----------------------------------------------------------------------------------------------------

## Test 3: Nmap → Katana → Nuclei (scanme)

  - Name: Test 3: Nmap → Katana → Nuclei
  - Agent Assignment: Pool → "Production Scanner Pool"
  - Step 1: nmap:quick_scan, target: scanme.nmap.org
  - Step 2: katana:crawl, url: http://scanme.nmap.org
  - Step 3: nuclei:info_scan, targets: {{json step2.output.urls}}

**Pre-requisites:**
1. The services for the asset scanme.nmap.org must be cleaned up before the workflows execution so that we can properly test the service enumeration via NMAP Scan.
2. The enumerated web endpoints for the asset scanme.nmap.org must be cleaned up before the workflows execution so that we can properly test the web endpoint enumeration via Katana crawling.
3. All the current running jobs must be killed
4. The agents from the Production Scanner Pool must be validated to understand if they have any stuck job or process
5. The backend/frontend should be restarted after all changes/fixes to see if compiling or other errors will happen
6. If the test is successful at the end, changes must be committed to git

**Success criteria:**
1. The services for the asset scanme.nmap.org will be enumerated via the nmap scan, including the tcp port 80, and they will be visible on the UI
2. tcp port 80 will be recognized as http during the nmap service scan, therefore, auto-tagged as web_application via our system auto-tagging feature
3. katana will be able to crawl the web endpoints from the asset scanme.nmap.org and they will be visible on UI
4. The output urls identified by Katana will be injected/sent to nuclei as targets (list)
5. Nuclei will be able to scan all the targets (web endpoints) previously identified by Katana using the info scan (severity -s)
6. All the objects will be shown in the asset graph with their correct relationship asset, ports/services, web endpoints
7. The workflow will be marked as completed and show on the UI under Workflows > executions
