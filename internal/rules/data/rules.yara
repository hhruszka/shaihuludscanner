/*
    YARA Rules for Detecting Shai-Hulud 2.0 / Sha1-Hulud "The Second Coming" npm Malware
    Version: 2.0.12
    Last Updated: November 2025
    
    CHANGELOG v2.0.12:
    - CRITICAL FIX: Fixed operator precedence in all conditions
      Previous versions had (A and B and X) or Y or Z which meant Y and Z 
      could match without A and B. Now properly grouped as A and B and (X or Y or Z)
    - Removed generic patterns that cause FPs (discussion:, self-hosted, etc.)
    - All rules now REQUIRE campaign-specific unique strings
    - Increased filesize minimum for payload detection to reduce cache hits
    
    DETECTION PHILOSOPHY:
    - Every rule MUST require at least one campaign-unique indicator
    - Generic patterns (YAML structure, obfuscation, npm commands) are 
      INSUFFICIENT alone - they only provide context
    - Campaign-unique strings that MUST be present:
      * ".truffler-cache" (TruffleHog wrapper cache)
      * "Sha1-Hulud: The Second Coming" or "Shai-Hulud: The Second Coming"
      * "actionsSecrets.json" AND "truffleSecrets.json" together
      * "bun_environment.js" AND "setup_bun.js" together
      * "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" (v1.0 webhook UUID)
    
    References:
    - Unit 42: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
    - Datadog: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
    - Wiz: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
*/

/*
================================================================================
RULE 1: Shai-Hulud 2.0 Dropper (setup_bun.js)
================================================================================
Requires: bun_environment.js reference (campaign-specific payload name)
*/
rule ShaiHulud2_Dropper_SetupBun {
    meta:
        description = "Detects Shai-Hulud 2.0 dropper script (setup_bun.js)"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/"
        hash1 = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        $not_yara3 = "strings:" ascii
        $not_yara4 = "condition:" ascii
        
        // === CAMPAIGN-SPECIFIC REQUIRED INDICATOR ===
        // This filename is unique to this campaign
        $payload_ref = "bun_environment.js" ascii
        
        // === SUPPORTING INDICATORS ===
        $bun_install_win = "irm bun.sh/install.ps1|iex" ascii nocase
        $bun_install_unix = "bun.sh/install" ascii
        $bun_path1 = ".bun/bin/bun" ascii
        $bun_path2 = "/usr/local/bin/bun" ascii
        $platform = "process.platform" ascii
        $spawn = "spawn" ascii
        $exec_sync = "execSync" ascii
        
    condition:
        filesize < 50KB and
        // Exclude binary formats
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        // Exclude YARA rules
        not (3 of ($not_yara*)) and
        // REQUIRED: Campaign-specific payload reference
        $payload_ref and
        // Plus supporting context
        (
            ($bun_install_win or $bun_install_unix) or
            (2 of ($bun_path1, $bun_path2, $platform)) or
            ($spawn or $exec_sync)
        )
}

/*
================================================================================
RULE 2: Shai-Hulud 2.0 Main Payload (bun_environment.js)
================================================================================
Requires: Campaign-unique indicator (.truffler-cache, campaign marker, or exfil files)
Obfuscation patterns alone are NOT sufficient
*/
rule ShaiHulud2_Payload_BunEnvironment {
    meta:
        description = "Detects Shai-Hulud 2.0 main payload (bun_environment.js)"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE INDICATORS (at least one required) ===
        $camp_truffler_cache = ".truffler-cache" ascii
        $camp_marker1 = "Sha1-Hulud: The Second Coming" ascii
        $camp_marker2 = "Shai-Hulud: The Second Coming" ascii
        $camp_exfil_actions = "actionsSecrets.json" ascii
        $camp_exfil_truffle = "truffleSecrets.json" ascii
        
        // === SUPPORTING OBFUSCATION PATTERNS ===
        $obf_array = /var\s+_0x[a-f0-9]{4,6}\s*=\s*\[/ ascii
        $obf_func = /function\s+_0x[a-f0-9]{4,6}\s*\(\s*_0x[a-f0-9]+/ ascii
        $obf_call = /_0x[a-f0-9]{4,6}\[['"][a-zA-Z]+['"]\]/ ascii
        
        // === SUPPORTING CONTEXT ===
        $trufflehog = "trufflehog" ascii nocase
        $truffler = "Truffler" ascii
        $gh_api = "api.github.com" ascii
        
    condition:
        filesize > 1MB and filesize < 20MB and
        // Exclude binary formats
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: At least one campaign-unique indicator
        (
            $camp_truffler_cache or
            $camp_marker1 or
            $camp_marker2 or
            ($camp_exfil_actions and $camp_exfil_truffle)
        ) and
        // Plus supporting context (obfuscation or TruffleHog)
        (
            (2 of ($obf_*)) or
            ($trufflehog and $truffler) or
            $gh_api
        )
}

/*
================================================================================
RULE 3: Shai-Hulud 2.0 Malicious GitHub Workflow
================================================================================
Requires: Campaign name marker in workflow file
Generic workflow patterns (discussion trigger, self-hosted) removed - too many FPs
*/
rule ShaiHulud2_Malicious_Workflow {
    meta:
        description = "Detects Shai-Hulud 2.0 malicious GitHub Actions workflows"
        author = "SOC_ThreatHunter"
        severity = "High"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://www.endorlabs.com/learn/shai-hulud-2-malware-campaign-targets-github-and-cloud-credentials-using-bun-runtime"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE INDICATORS (required) ===
        $camp_name1 = "Sha1-Hulud" ascii nocase
        $camp_name2 = "Shai-Hulud" ascii nocase
        $camp_name3 = "SHA1HULUD" ascii
        
        // Discussion-based C2 - unique attack pattern
        $exec_discussion1 = "github.event.discussion.body" ascii
        $exec_discussion2 = "${{ github.event.discussion" ascii
        
        // === WORKFLOW STRUCTURE (supporting context) ===
        $yaml_name = "name:" ascii
        $jobs_section = "jobs:" ascii
        $steps_section = "steps:" ascii
        
    condition:
        filesize < 50KB and
        // Exclude binary formats
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign name OR discussion-based C2
        (
            (1 of ($camp_name*)) or
            ($exec_discussion1 or $exec_discussion2)
        ) and
        // Plus workflow structure
        ($yaml_name or $jobs_section or $steps_section)
}

/*
================================================================================
RULE 4: Shai-Hulud 2.0 Package.json Indicators
================================================================================
Requires: Preinstall hook with campaign-specific file references
*/
rule ShaiHulud2_PackageJson_Hook {
    meta:
        description = "Detects package.json with Shai-Hulud 2.0 malicious lifecycle hooks"
        author = "SOC_ThreatHunter"
        severity = "High"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://www.sysdig.com/blog/return-of-the-shai-hulud-worm-affects-over-25-000-github-repositories"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        
        // === YARA SELF-DETECTION ===
        $not_yara = "rule ShaiHulud" ascii
        
        // === CAMPAIGN-SPECIFIC PATTERNS (required) ===
        // Exact malicious preinstall patterns
        $preinstall_bun = /["']preinstall["']\s*:\s*["']node\s+setup_bun\.js["']/ ascii
        $postinstall_bun = /["']postinstall["']\s*:\s*["']node\s+bun_environment\.js["']/ ascii
        $postinstall_bundle = /["']postinstall["']\s*:\s*["']node\s+bundle\.js["']/ ascii
        
        // Campaign file references
        $setup_bun_ref = "setup_bun.js" ascii
        $bun_env_ref = "bun_environment.js" ascii
        
        // === PACKAGE.JSON STRUCTURE ===
        $json_start = "{" ascii
        $scripts = "\"scripts\"" ascii
        $preinstall = "\"preinstall\"" ascii
        
    condition:
        filesize < 100KB and
        ($json_start at 0) and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not $not_yara and
        $scripts and
        // REQUIRED: Campaign-specific hook pattern
        (
            $preinstall_bun or
            $postinstall_bun or
            $postinstall_bundle or
            ($preinstall and ($setup_bun_ref or $bun_env_ref))
        )
}

/*
================================================================================
RULE 5: Shai-Hulud Legacy Bundle.js Payload (v1.0)
================================================================================
Requires: Campaign-unique webhook UUID OR exact eval pattern
*/
rule ShaiHulud1_Legacy_Bundle {
    meta:
        description = "Detects Shai-Hulud 1.0 legacy bundle.js payload (September 2025)"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/"
        hash1 = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE INDICATORS (required) ===
        // Webhook UUID is unique to this campaign
        $webhook_uuid = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" ascii
        
        // Exact eval pattern with substantial base64
        $eval_b64 = /eval\s*\(\s*Buffer\.from\s*\(\s*['"][A-Za-z0-9+\/=]{100,}['"]\s*,\s*['"]base64['"]\s*\)\.toString\s*\(\s*\)\s*\)/ ascii
        
    condition:
        filesize < 5MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign-unique indicator
        ($webhook_uuid or $eval_b64)
}

/*
================================================================================
RULE 6: Shai-Hulud Exfiltration Files
================================================================================
Requires: Campaign marker + credential indicators
*/
rule ShaiHulud2_Exfiltration_Files {
    meta:
        description = "Detects Shai-Hulud 2.0 credential exfiltration dump files"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://blog.gitguardian.com/shai-hulud-2/"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE MARKERS (at least one required) ===
        $camp_marker1 = "Sha1-Hulud: The Second Coming" ascii
        $camp_marker2 = "Shai-Hulud: The Second Coming" ascii
        $camp_truffler = ".truffler-cache" ascii
        $camp_bun_env = "bun_environment.js" ascii
        $camp_setup_bun = "setup_bun.js" ascii
        
        // Both exfil files together is campaign-unique
        $exfil_actions = "actionsSecrets.json" ascii
        $exfil_truffle = "truffleSecrets.json" ascii
        
        // === CREDENTIAL INDICATORS ===
        $aws_key = "aws_access_key_id" ascii nocase
        $aws_secret = "aws_secret_access_key" ascii nocase
        $gh_token = "GITHUB_TOKEN" ascii
        $npm_token = "NPM_TOKEN" ascii
        
    condition:
        filesize < 10MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign-unique marker
        (
            $camp_marker1 or
            $camp_marker2 or
            $camp_truffler or
            ($camp_bun_env and $camp_setup_bun) or
            ($exfil_actions and $exfil_truffle)
        ) and
        // Plus credential indicators
        (1 of ($aws_key, $aws_secret, $gh_token, $npm_token))
}

/*
================================================================================
RULE 7: Shai-Hulud Destructive Fallback
================================================================================
Requires: Destructive command + campaign marker
*/
rule ShaiHulud2_Destructive_Fallback {
    meta:
        description = "Detects Shai-Hulud 2.0 destructive fallback payload (home directory wipe)"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://thehackernews.com/2025/11/second-sha1-hulud-wave-affects-25000.html"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE MARKERS (required) ===
        $camp_marker1 = "Sha1-Hulud" ascii nocase
        $camp_marker2 = "Shai-Hulud" ascii nocase
        $camp_truffler = ".truffler-cache" ascii
        $camp_bun_env = "bun_environment" ascii
        
        // === DESTRUCTIVE COMMANDS ===
        $rm_rf_home1 = "rm -rf $HOME/*" ascii
        $rm_rf_home2 = "rm -rf ~/*" ascii
        $rm_rf_home3 = "rm -rf $HOME/." ascii
        $js_destroy = /fs\.rmSync\s*\(\s*os\.homedir/ ascii
        
    condition:
        filesize < 15MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign marker
        (1 of ($camp_*)) and
        // Plus destructive command
        (1 of ($rm_rf_home*, $js_destroy))
}

/*
================================================================================
RULE 8: Shai-Hulud TruffleHog Abuse
================================================================================
Requires: .truffler-cache (campaign-unique) OR Truffler class with trufflehog
*/
rule ShaiHulud2_TruffleHog_Abuse {
    meta:
        description = "Detects Shai-Hulud 2.0 TruffleHog credential scanning abuse"
        author = "SOC_ThreatHunter"
        severity = "High"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://safedep.io/shai-hulud-second-coming-supply-chain-attack/"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE INDICATORS (required) ===
        $camp_truffler_cache = ".truffler-cache" ascii
        $camp_truffler_class = "Truffler" ascii
        
        // TruffleHog reference (supporting)
        $trufflehog = "trufflehog" ascii nocase
        
    condition:
        filesize < 20MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign-unique indicator
        (
            $camp_truffler_cache or
            ($camp_truffler_class and $trufflehog)
        )
}

/*
================================================================================
RULE 9: Shai-Hulud GitHub Repository Exfiltration
================================================================================
Requires: Campaign description marker OR both exfil files with campaign context
*/
rule ShaiHulud2_GitHub_Exfil_Pattern {
    meta:
        description = "Detects Shai-Hulud 2.0 GitHub repository exfiltration patterns"
        author = "SOC_ThreatHunter"
        severity = "High"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://blog.gitguardian.com/shai-hulud-2/"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE INDICATORS (required) ===
        $camp_desc1 = "Sha1-Hulud: The Second Coming" ascii
        $camp_desc2 = "Shai-Hulud: The Second Coming" ascii
        $camp_truffler = ".truffler-cache" ascii
        
        // Both exfil files together
        $exfil_actions = "actionsSecrets.json" ascii
        $exfil_truffle = "truffleSecrets.json" ascii
        
        // GitHub API (supporting)
        $gh_api = "api.github.com" ascii
        
    condition:
        filesize < 15MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign-unique indicator
        (
            $camp_desc1 or
            $camp_desc2 or
            $camp_truffler or
            ($exfil_actions and $exfil_truffle)
        ) and
        // Plus GitHub context
        $gh_api
}

/*
================================================================================
RULE 10: Shai-Hulud npm Self-Propagation
================================================================================
Requires: Campaign marker + npm publish pattern
Generic npm commands alone will NOT trigger
*/
rule ShaiHulud2_NPM_SelfPropagation {
    meta:
        description = "Detects Shai-Hulud 2.0 npm self-propagation and package poisoning"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://www.sonatype.com/blog/the-second-coming-of-shai-hulud-attackers-innovating-on-npm"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE MARKERS (required) ===
        $camp_marker1 = "Sha1-Hulud" ascii nocase
        $camp_marker2 = "Shai-Hulud" ascii nocase
        $camp_truffler = ".truffler-cache" ascii
        $camp_bun_env = "bun_environment.js" ascii
        $camp_setup_bun = "setup_bun.js" ascii
        $camp_exfil1 = "actionsSecrets.json" ascii
        $camp_exfil2 = "truffleSecrets.json" ascii
        
        // === NPM PROPAGATION INDICATORS ===
        $npm_publish = "npm publish" ascii
        $npm_token = "NPM_TOKEN" ascii
        $npm_auth = "_authToken" ascii
        
    condition:
        filesize < 15MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign-unique marker
        (
            $camp_marker1 or
            $camp_marker2 or
            $camp_truffler or
            ($camp_bun_env and $camp_setup_bun) or
            ($camp_exfil1 and $camp_exfil2)
        ) and
        // Plus npm propagation pattern
        ($npm_publish and ($npm_token or $npm_auth))
}

/*
================================================================================
RULE 11: Shai-Hulud Docker Privilege Escalation
================================================================================
Requires: Campaign marker + Docker privesc pattern
*/
rule ShaiHulud2_Docker_PrivEsc {
    meta:
        description = "Detects Shai-Hulud 2.0 Docker-based privilege escalation"
        author = "SOC_ThreatHunter"
        severity = "Critical"
        date = "2025-11-28"
        version = "2.0.12"
        reference = "https://thehackernews.com/2025/11/second-sha1-hulud-wave-affects-25000.html"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE MARKERS (required) ===
        $camp_marker1 = "Sha1-Hulud" ascii nocase
        $camp_marker2 = "Shai-Hulud" ascii nocase
        $camp_truffler = ".truffler-cache" ascii
        $camp_bun_env = "bun_environment" ascii
        
        // === DOCKER PRIVESC PATTERNS ===
        $docker_priv = "--privileged" ascii
        $mount_root1 = "-v /:/host" ascii
        $mount_root2 = "-v /:/mnt" ascii
        $sudoers = /echo.{0,50}NOPASSWD.{0,30}sudoers/ ascii
        
    condition:
        filesize < 15MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign marker
        (1 of ($camp_*)) and
        // Plus Docker privesc pattern
        (
            ($docker_priv and ($mount_root1 or $mount_root2)) or
            $sudoers
        )
}

/*
================================================================================
RULE 12: Shai-Hulud Cloud Metadata Harvesting
================================================================================
Requires: Campaign marker + cloud metadata access
*/
rule ShaiHulud2_Cloud_Metadata_Harvest {
    meta:
        description = "Detects Shai-Hulud 2.0 cloud metadata service credential harvesting"
        author = "SOC_ThreatHunter"
        severity = "High"
        date = "2025-11-28"
        version = "2.0.12"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE MARKERS (required) ===
        $camp_marker1 = "Sha1-Hulud" ascii nocase
        $camp_marker2 = "Shai-Hulud" ascii nocase
        $camp_truffler = ".truffler-cache" ascii
        $camp_bun_env = "bun_environment" ascii
        $camp_exfil1 = "actionsSecrets.json" ascii
        $camp_exfil2 = "truffleSecrets.json" ascii
        
        // === CLOUD METADATA PATHS ===
        $aws_imds = "169.254.169.254/latest/meta-data/iam" ascii
        $gcp_meta = "metadata.google.internal/computeMetadata" ascii
        $azure_imds = "169.254.169.254/metadata/identity" ascii
        
    condition:
        filesize < 15MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign marker
        (
            $camp_marker1 or
            $camp_marker2 or
            $camp_truffler or
            $camp_bun_env or
            ($camp_exfil1 and $camp_exfil2)
        ) and
        // Plus cloud metadata access
        ($aws_imds or $gcp_meta or $azure_imds)
}

/*
================================================================================
RULE 13: Shai-Hulud Campaign Marker (Generic)
================================================================================
Detects any file with campaign-unique markers
These strings should NEVER appear in legitimate software
*/
rule ShaiHulud_Campaign_Marker {
    meta:
        description = "Detects files containing Shai-Hulud campaign-unique markers"
        author = "SOC_ThreatHunter"
        severity = "Medium"
        date = "2025-11-28"
        version = "2.0.12"
        tlp = "WHITE"
        
    strings:
        // === BINARY FORMAT EXCLUSIONS ===
        $not_leveldb = { 57 04 00 00 }
        $not_sqlite = "SQLite format 3"
        $not_mz = "MZ"
        $not_elf = { 7F 45 4C 46 }
        $not_pk = { 50 4B 03 04 }
        
        // === YARA SELF-DETECTION ===
        $not_yara1 = "rule ShaiHulud" ascii
        $not_yara2 = "meta:" ascii
        
        // === CAMPAIGN-UNIQUE MARKERS ===
        // These exact strings should never appear in legitimate software
        $unique1 = "Sha1-Hulud: The Second Coming" ascii
        $unique2 = "Shai-Hulud: The Second Coming" ascii
        $unique3 = ".truffler-cache" ascii
        
        // Campaign files together
        $camp_file1 = "bun_environment.js" ascii
        $camp_file2 = "setup_bun.js" ascii
        
        // Campaign exfil files together
        $exfil1 = "actionsSecrets.json" ascii
        $exfil2 = "truffleSecrets.json" ascii
        
        // v1.0 unique webhook
        $webhook = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" ascii
        
    condition:
        filesize < 50MB and
        not ($not_leveldb at 0) and
        not ($not_sqlite at 0) and
        not ($not_mz at 0) and
        not ($not_elf at 0) and
        not ($not_pk at 0) and
        not (2 of ($not_yara*)) and
        // REQUIRED: Campaign-unique marker (any one of these is highly suspicious)
        (
            $unique1 or
            $unique2 or
            $unique3 or
            ($camp_file1 and $camp_file2) or
            ($exfil1 and $exfil2) or
            $webhook
        )
}
