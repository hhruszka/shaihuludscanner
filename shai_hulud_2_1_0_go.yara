/*
    YARA Rules for Shai-Hulud 2.0 Detection - Go Scanner Optimized
    Version: 2.1.0
    
    REQUIREMENTS:
    - Scanner must define external variables: filename, filepath
    - Scanner should pre-filter with shouldScan() for performance
    
    EXPECTED PRE-FILTERING (shouldScan):
    - package.json
    - setup_bun.js
    - bun_environment.js
    - bundle.js
    - actionsSecrets.json
    - truffleSecrets.json
    - *.js in node_modules
    - *.yml/*.yaml in .github/workflows
    - Any file in .truffler-cache directory
*/

// =============================================================================
// TIER 1: CRITICAL - Definitive infection indicators
// =============================================================================

// NOTE: .truffler-cache directory detection is handled in Go walker
// This rule detects references to .truffler-cache in code

rule ShaiHulud2_TrufflerCache_String {
    meta:
        description = "Reference to .truffler-cache in code"
        severity = "Critical"
        tier = "1"
    strings:
        $cache = ".truffler-cache"
    condition:
        $cache
}

rule ShaiHulud2_Campaign_Description {
    meta:
        description = "Campaign description string"
        severity = "Critical"
        tier = "1"
    strings:
        $desc1 = "Sha1-Hulud: The Second Coming"
        $desc2 = "Shai-Hulud: The Second Coming"
    condition:
        any of them
}

rule ShaiHulud1_Webhook_UUID {
    meta:
        description = "v1.0 webhook UUID"
        severity = "Critical"
        tier = "1"
    strings:
        $uuid = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
    condition:
        $uuid
}

rule ShaiHulud2_Exfil_Artifacts {
    meta:
        description = "Exfiltration artifact files"
        severity = "Critical"
        tier = "1"
    condition:
        filename == "actionsSecrets.json" or
        filename == "truffleSecrets.json"
}

rule ShaiHulud2_Exfil_References {
    meta:
        description = "Both exfil filenames referenced in code"
        severity = "Critical"
        tier = "1"
    strings:
        $exfil1 = "actionsSecrets.json"
        $exfil2 = "truffleSecrets.json"
    condition:
        $exfil1 and $exfil2
}

// =============================================================================
// TIER 2: HIGH - Filename + content confirmation
// =============================================================================

rule ShaiHulud2_Dropper {
    meta:
        description = "setup_bun.js dropper"
        severity = "Critical"
        tier = "2"
    strings:
        $payload = "bun_environment.js"
        $install1 = "bun.sh/install"
        $install2 = "irm bun.sh/install.ps1"
    condition:
        filename == "setup_bun.js" and
        ($payload or $install1 or $install2)
}

rule ShaiHulud2_Payload {
    meta:
        description = "bun_environment.js payload"
        severity = "Critical"
        tier = "2"
    strings:
        $truffler1 = ".truffler-cache"
        $truffler2 = "Truffler"
        $trufflehog = "trufflehog" nocase
        $exfil1 = "actionsSecrets.json"
        $exfil2 = "truffleSecrets.json"
    condition:
        filename == "bun_environment.js" and
        ($truffler1 or ($truffler2 and $trufflehog) or ($exfil1 and $exfil2))
}

rule ShaiHulud1_Legacy_Payload {
    meta:
        description = "bundle.js v1.0 payload"
        severity = "Critical"
        tier = "2"
    strings:
        $eval = "eval(Buffer.from"
        $b64 = "base64').toString()"
        $webhook = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
    condition:
        filename == "bundle.js" and
        ($webhook or ($eval and $b64))
}

rule ShaiHulud2_PackageJson_Hook {
    meta:
        description = "Malicious package.json lifecycle hook"
        severity = "High"
        tier = "2"
    strings:
        $pre_setup = /["']preinstall["']\s*:\s*["'][^"']*setup_bun\.js/
        $pre_bun = /["']preinstall["']\s*:\s*["'][^"']*bun_environment\.js/
        $post_bun = /["']postinstall["']\s*:\s*["'][^"']*bun_environment\.js/
        $post_bundle = /["']postinstall["']\s*:\s*["'][^"']*bundle\.js/
    condition:
        filename == "package.json" and
        any of them
}

rule ShaiHulud2_Workflow {
    meta:
        description = "Malicious GitHub workflow"
        severity = "High"
        tier = "2"
    strings:
        $marker1 = "Sha1-Hulud" nocase
        $marker2 = "Shai-Hulud" nocase
        $marker3 = "SHA1HULUD"
    condition:
        any of ($marker*)
}

// =============================================================================
// TIER 3: MEDIUM - Supporting indicators (combine with other findings)
// =============================================================================

rule ShaiHulud2_Truffler_Wrapper {
    meta:
        description = "TruffleHog wrapper class pattern"
        severity = "Medium"
        tier = "3"
    strings:
        $class = "Truffler"
        $tool = "trufflehog" nocase
        $exec1 = "trufflehog filesystem"
        $exec2 = "trufflehog git"
    condition:
        $class and ($tool or $exec1 or $exec2)
}

rule ShaiHulud2_Campaign_Files_Together {
    meta:
        description = "Both campaign files referenced together"
        severity = "Medium"
        tier = "3"
    strings:
        $dropper = "setup_bun.js"
        $payload = "bun_environment.js"
    condition:
        $dropper and $payload
}

rule ShaiHulud2_Bun_Install_Pattern {
    meta:
        description = "Bun installation with payload reference"
        severity = "Medium"
        tier = "3"
    strings:
        $install1 = "bun.sh/install"
        $install2 = "irm bun.sh/install.ps1"
        $payload = "bun_environment.js"
        $check1 = "which bun"
        $check2 = "where bun"
    condition:
        ($install1 or $install2) and $payload and ($check1 or $check2)
}

rule ShaiHulud2_GitHub_Exfil_Pattern {
    meta:
        description = "GitHub API exfiltration pattern"
        severity = "Medium"
        tier = "3"
    strings:
        $api = "api.github.com"
        $exfil1 = "actionsSecrets"
        $exfil2 = "truffleSecrets"
        $desc = "Second Coming"
    condition:
        $api and (($exfil1 and $exfil2) or $desc)
}
