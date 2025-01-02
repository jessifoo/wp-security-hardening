# WordPress Security Hardening Plugin

(NEVER CHANGE THIS PARAGRAPH)
A zero-maintenance security plugin designed to protect WordPress sites on shared hosting. It automates malware prevention, detection, and resolution while keeping WordPress core and plugins updated to the latest versions.

The issue is that hostinger malware scans arent finding the malware that's somehow constantly getting into my three wordpress sites, there are 0 byte files with names fhfiu4h2.php litered everywhere and even the js is broken on one of the sites so i can't login to the admin dashboard. I want a plugin that I can upload to the plugin directory and it will just start working without me having to do anything and maybe even help the other sites too but i can upload the plugin to each one, there is probably bad stuff in the db as well

## Solution Approach

### 1. Immediate Response
- Detects and removes zero-byte PHP files
- Restores compromised JavaScript files
- Cleans database of malicious content
- Repairs admin access

### 2. Complete File Restoration
- Downloads fresh WordPress core files from WordPress.org
- Verifies file integrity using official checksums
- Replaces all core files with clean versions
- Restores plugins from WordPress.org repository

### 3. Self-Protection
- Maintains own integrity through Git repository
- Auto-restores if compromised
- Continuous integrity monitoring
- Scheduled verification checks

### 4. Cross-Site Protection
- Shares threat intelligence between sites
- Coordinates malware signatures
- Maintains shared blocklists
- Efficient resource usage

### 5. Prevention
- Blocks unauthorized file creation
- Monitors file system changes
- Prevents PHP execution in uploads
- Hardens WordPress security

## Target Sites

- jessica-johnson.ca
- rayzgyproc.com
- spectrapsychology.com

All sites share API free tier limits and run on a shared Hostinger account.

## Features

### Automatic Updates and Integrity Verification

- **Core Updates**: Automatically updates WordPress core files and verifies their integrity
- **Plugin Updates**: Keeps plugins up-to-date and checks for compromised files
- **File Integrity**: Regularly scans and repairs modified core and plugin files
- **wp-config.php Protection**: Monitors and restores wp-config.php if compromised

### Malware Prevention and Cleaning

- **Active Scanning**: Continuously monitors for suspicious files and code
- **Automatic Removal**: Quarantines and removes detected malware
- **Code Analysis**: Detects obfuscated and malicious code patterns
- **File System Protection**: Prevents unauthorized file creation and modification

### Cross-Site Protection

- **Shared Intelligence**: Coordinates security measures across multiple sites
- **Rate Limiting**: Manages API usage across sites to stay within free tier limits
- **Centralized Logging**: Aggregates security events from all sites
- **Unified Notifications**: Sends alerts for critical events across all sites

## Architecture

### Directory Structure

The plugin follows a layered architecture with clear separation of concerns:

```
includes/
├── Core/           # Core Utilities Layer
│   ├── Api/        # API interaction and rate limiting
│   ├── Logger/     # Centralized logging system
│   └── Utils/      # Common utilities
├── Security/       # Security Layer
│   ├── Scanner/    # File and malware scanning
│   │   ├── Malware/      # Malware detection components
│   │   │   ├── class-malware-detector.php     # Main malware scanning
│   │   │   └── class-threat-pattern-manager.php # Pattern management
│   ├── Analyzer/   # Code and pattern analysis
│   └── Intelligence/ # Threat detection and management
├── Repair/         # Repair Layer
│   ├── Core/       # WordPress core repairs
│   ├── Plugin/     # Plugin file repairs
│   └── Database/   # Database cleaning and optimization
├── Monitoring/     # Monitoring Layer
│   ├── Health/     # System health checks
│   ├── Resource/   # Resource usage monitoring
│   └── Optimization/ # WordPress and hosting optimizations
├── Network/        # Network Layer
│   ├── Coordinator/ # Site coordination
│   ├── Integration/ # Plugin integrations
│   └── Protection/  # Login and IP security
└── System/         # System Layer
    ├── Cron/       # Scheduled tasks
    └── Update/     # Updates management
```

### Component Layers

The plugin is organized into hierarchical layers, with each layer depending on the layers below it:

1. **Core Utilities Layer**
   - `class-api-utils.php`: API interaction and rate limiting
   - `class-logger.php`: Centralized logging system

2. **Security Layer**
   - `class-threat-intelligence.php`: Threat detection and pattern management
   - `class-security-scanner.php`: Base scanning functionality
   - `class-file-integrity.php`: File monitoring
   - `class-malware-detector.php`: Malware scanning
   - `class-code-analyzer.php`: Code analysis
   - `class-infection-tracer.php`: Infection tracking
   - `class-ai-security.php`: AI-powered analysis

3. **Repair Layer**
   - `class-core-repair.php`: WordPress core repairs
   - `class-plugin-repair.php`: Plugin file repairs
   - `class-quarantine-manager.php`: File quarantine
   - `class-htaccess-cleaner.php`: .htaccess management
   - `class-db-cleaner.php`: Database cleaning

4. **Monitoring Layer**
   - `class-health-monitor.php`: System health checks
   - `class-resource-monitor.php`: Resource usage monitoring
   - `class-wp-optimizations.php`: WordPress optimizations
   - `class-hostinger-optimizations.php`: Hosting-specific optimizations
   - `class-litespeed-optimizer.php`: LiteSpeed optimizations

5. **Network Layer**
   - `class-site-coordinator.php`: Site coordination
   - `class-ip-manager.php`: IP management
   - `class-login-hardening.php`: Login security
   - `class-plugin-integrations.php`: Plugin integrations

6. **System Layer**
   - `class-cron-manager.php`: Scheduled tasks
   - `class-update-manager.php`: Updates management

### Component Dependencies

**Core Dependencies:**
- Logger: Required by all components for operation logging
- API Utils: Required for external API interactions and rate limiting
- Pattern Manager: Required for security pattern management
- Rate Limiter: Required for API management

**Feature Dependencies:**
- File Integrity → Logger, Quarantine Manager
- Threat Intelligence → API Utils, Logger, Pattern Manager
- Malware Detector → API Utils, Quarantine Manager
- Update Manager → API Utils, Core Repair

### API Integration

The plugin integrates with multiple external APIs:

1. VirusTotal: Malware scanning
2. AbuseIPDB: IP reputation
3. OpenAI: AI analysis
4. CloudFlare: IP blocking

API usage is coordinated across all sites to stay within free tier limits.

### Development Guidelines

1. **Dependency Management**
   - Initialize base services first
   - Check dependencies in constructors
   - Use dependency injection
   - Follow WordPress coding standards

2. **Cross-Site Coordination**
   - Share API limits across all sites
   - Coordinate scheduled tasks
   - Centralize logging and notifications

3. **Error Handling**
   - Log all critical operations
   - Implement proper fallbacks
   - Handle API failures gracefully
   - Maintain audit trail

4. **Performance**
   - Optimize scanning operations
   - Use WordPress transients for caching
   - Use batch processing for heavy tasks
   - Monitor resource usage

## Implementation Status

### Completed
- [x] Core architecture and dependency management
- [x] Base services (Logger, API Utils)
- [x] Pattern management system
- [x] API rate limiting
- [x] File integrity monitoring
- [x] Basic malware detection

### In Progress
- [ ] Advanced malware detection with AI
- [ ] Admin interface improvements
- [ ] Cross-site threat intelligence sharing
- [ ] Performance optimization for large sites


To ensure no undefined or incomplete functions are left in the implementation, let’s expand on the key pieces of the architecture and explicitly detail their required functionality, inputs, and outputs. This will ensure clarity and consistency when writing or refactoring the codebase.

1. Core File Restoration

Functionality:
	•	Download and verify WordPress core files.
	•	Replace existing files while preserving critical configurations (wp-config.php, .htaccess).
	•	Quarantine suspicious files before deletion.

Implementation Plan:

Class: FileRestorer
	•	Methods:
   1.	downloadCoreFiles():
      •	Input: WordPress version (optional; defaults to the latest).
      •	Output: Path to downloaded core files.
      •	Logic:
      •	Fetch the download URL from the WordPress Core API.
      •	Verify checksum after downloading.
      •	Extract files to a temporary directory.
   2.	verifyCoreFiles():
      •	Input: Path to downloaded files.
      •	Output: True if all files pass checksum validation, otherwise false.
      •	Logic:
      •	Compare each file’s checksum with official checksums.
   3.	replaceCoreFiles():
      •	Input: Path to verified files.
      •	Output: Success or failure message.
      •	Logic:
      •	Replace all files except those flagged (e.g., wp-config.php).
      •	Quarantine flagged files instead of deleting them.

2. Plugin and Theme Restoration

Functionality:
	•	Replace all plugin and theme files with verified clean copies.
	•	Identify and restore only active plugins/themes.

Implementation Plan:

Class: PluginRestorer
	•	Methods:
	1.	getActivePlugins():
      •	Output: List of active plugins (plugin-folder/plugin-file.php).
      •	Logic:
         •	Read active_plugins option from the database.
	2.	downloadPlugin():
      •	Input: Plugin slug.
      •	Output: Path to downloaded plugin files.
      •	Logic:
         • Use the WordPress Plugin API to fetch the download link.
         • Verify checksum after downloading.
	3.	replacePluginFiles():
      •	Input: Path to plugin files.
      •	Output: Success or failure message.
      •	Logic:
         •	Replace all plugin files with verified versions.
         •	Quarantine any unknown or suspicious files.

Class: ThemeRestorer
	•	Methods:
	1.	getActiveThemes():
	   •	Output: List of active themes.
	   •	Logic:
	      •	Read stylesheet and template options from the database.
	2.	downloadTheme():
	   •	Input: Theme slug.
	   •	Output: Path to downloaded theme files.
	   •	Logic:
	      •	Use the WordPress Theme API to fetch the download link.
	      •	Verify checksum after downloading.
	3.	replaceThemeFiles():
	   •	Input: Path to theme files.
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Replace all theme files with verified versions.
	      •	Quarantine suspicious files.

3. Self-Protection

Functionality:
	•	Verify plugin integrity against a GitHub repository.
	•	Restore plugin files if tampered with.
	•	Retain user settings during restoration.

Implementation Plan:

Class: SelfRestorer
	•	Methods:
	1.	verifySelfIntegrity():
	   •	Output: True if plugin files match GitHub repository, otherwise false.
	   •	Logic:
	      •	Compare each file’s hash with the corresponding hash in the GitHub repository.
	2.	restorePlugin():
	   •	Input: None.
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Download clean plugin files from GitHub.
	      •	Replace existing files while retaining settings in the database.

4. Malware Detection and Removal

Functionality:
	•	Identify and remove zero-byte files and malicious code.
	•	Scan and clean the database for malicious injections.

Implementation Plan:

Class: MalwareCleaner
	•	Methods:
	1.	scanZeroByteFiles():
	   •	Output: List of zero-byte files.
	   •	Logic:
	      •	Recursively scan the WordPress directory for files with size 0.
	2.	removeZeroByteFiles():
	   •	Input: List of zero-byte files.
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Delete all identified zero-byte files.
	3.	scanDatabase():
	   •	Output: List of infected database entries.
	   •	Logic:
	      •	Check common tables (wp_options, wp_posts, etc.) for known malicious patterns.
	4.	cleanDatabase():
	   •	Input: List of infected database entries.
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Remove or sanitize malicious entries.

5. Scheduled Integrity Monitoring

Functionality:
	•	Regularly verify the integrity of all files and database entries.
	•	Trigger automatic restoration if issues are detected.

Implementation Plan:

Class: IntegrityMonitor
	•	Methods:
	1.	scheduleChecks():
	   •	Output: Scheduled cron event.
	   •	Logic:
	      •	Use wp_schedule_event to schedule periodic checks.
	2.	verifyIntegrity():
	   •	Output: Report of discrepancies or issues.
	   •	Logic:
	      •	Compare current file and database states with verified clean states.
	3.	triggerRestoration():
	   •	Input: List of issues detected.
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Call FileRestorer, PluginRestorer, or SelfRestorer as needed.

6. Cross-Site Protection

Functionality:
	•	Share threat intelligence across sites using the plugin.
	•	Maintain shared blocklists for IPs and malware signatures.

Implementation Plan:

Class: ThreatIntelligence
	•	Methods:
	1.	shareThreatPatterns():
	   •	Input: List of new threat patterns.
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Update all connected sites with the new patterns via API.
	2.	syncBlocklists():
	   •	Output: Success or failure message.
	   •	Logic:
	      •	Synchronize IP and malware blocklists across sites.

How to Enforce This During Development
	1.	Complete Function Definitions:
	   •	Enforce that every function includes inputs, outputs, and logic or explicit placeholders with explanations.
	2.	Code Reviews:
	   •	Regularly review code to ensure no incomplete methods or ambiguous placeholders are left behind.
	3.	Automated Testing:
	   •	Implement unit tests for all major components to verify completeness and functionality.

Checking file integrity and verifying checksums involves comparing the contents of existing files against trusted sources. This ensures the files are authentic and unmodified. Here’s how it works:

1. General Steps for File Integrity Verification
	1.	Retrieve Original Checksums:
	   •	Obtain a list of file checksums from a trusted source (e.g., WordPress.org or GitHub).
	   •	The checksum list typically contains file paths and their corresponding hash values (e.g., MD5 or SHA256).
	2.	Generate Local Checksums:
	   •	Compute the hash of each file in the local WordPress installation.
	3.	Compare Checksums:
	   •	Match the locally generated checksum for each file with the corresponding checksum from the trusted source.
	   •	If there’s a mismatch, the file may be corrupted or tampered with.
	4.	Report or Replace Tampered Files:
	   •	Identify and log files with mismatched checksums.
	   •	Replace the tampered files with clean versions from the trusted source.

2. Technical Implementation

A. Retrieve Original Checksums
	•	WordPress.org provides an API for retrieving core file checksums:
	•	API Endpoint: https://api.wordpress.org/core/checksums/1.0/
	•	Example Request:

`GET https://api.wordpress.org/core/checksums/1.0/?version=6.3.1&locale=en_US`


	•	Response:

```bash
{
    "checksums": {
        "wp-admin/index.php": "5d41402abc4b2a76b9719d911017c592",
        "wp-includes/version.php": "81dc9bdb52d04dc20036dbd8313ed055",
        ...
    }
}
```


B. Generate Local Checksums
	•	Use PHP’s hash_file function to compute the hash of a local file:

`$local_checksum = hash_file('md5', ABSPATH . 'wp-admin/index.php');`



C. Compare Checksums
	•	Compare the local checksum against the trusted checksum:
```bash
$trusted_checksum = '5d41402abc4b2a76b9719d911017c592';
if ($local_checksum === $trusted_checksum) {
    echo 'File is intact.';
} else {
    echo 'File is tampered with.';
}
```


D. Replace Tampered Files
	•	If a file is tampered with, download a clean copy from the trusted source and replace it:
```bash
$url = 'https://wordpress.org/latest.zip';
$destination = ABSPATH . 'wp-admin/index.php';
file_put_contents($destination, file_get_contents($url));
```

3. File Integrity Checker: Implementation Plan

Class: FileIntegrityChecker

Methods:
	1.	getTrustedChecksums():
	•	Input: WordPress version, locale.
	•	Output: Associative array of file paths and their checksums.
	•	Logic:
	•	Use the WordPress.org Checksums API.
	•	Parse the JSON response into an array.
	•	Code:

```bash
public function getTrustedChecksums($version, $locale = 'en_US') {
    $url = "https://api.wordpress.org/core/checksums/1.0/?version=$version&locale=$locale";
    $response = wp_remote_get($url);
    if (is_wp_error($response)) {
        return [];
    }
    $data = json_decode(wp_remote_retrieve_body($response), true);
    return $data['checksums'] ?? [];
}
```

	2.	calculateLocalChecksum():
	•	Input: Path to the local file.
	•	Output: Checksum string (e.g., MD5 hash).
	•	Code:

```bash
public function calculateLocalChecksum($file_path) {
    return hash_file('md5', $file_path);
}
```

	3.	verifyFileIntegrity():
	•	Input: Path to the local file, trusted checksum.
	•	Output: True if checksums match, otherwise false.
	•	Code:

```bash
public function verifyFileIntegrity($file_path, $trusted_checksum) {
    $local_checksum = $this->calculateLocalChecksum($file_path);
    return $local_checksum === $trusted_checksum;
}
```

	4.	scanAllFiles():
	•	Input: Associative array of file paths and their trusted checksums.
	•	Output: List of tampered files.
	•	Logic:
	•	Loop through each file path.
	•	Compare local checksum with the trusted checksum.
	•	Collect paths of tampered files.
	•	Code:

```bash
public function scanAllFiles($checksums) {
    $tampered_files = [];
    foreach ($checksums as $file => $trusted_checksum) {
        $file_path = ABSPATH . $file;
        if (!file_exists($file_path)) {
            $tampered_files[] = $file;
            continue;
        }
        if (!$this->verifyFileIntegrity($file_path, $trusted_checksum)) {
            $tampered_files[] = $file;
        }
    }
    return $tampered_files;
}
```

	5.	replaceTamperedFiles():
	•	Input: List of tampered files.
	•	Output: Success or failure message.
	•	Logic:
	•	Download clean versions of tampered files.
	•	Replace them in the WordPress directory.
	•	Code:

```bash
public function replaceTamperedFiles($tampered_files) {
    foreach ($tampered_files as $file) {
        $clean_url = "https://wordpress.org/latest/$file"; // Example URL
        $destination = ABSPATH . $file;
        $clean_content = file_get_contents($clean_url);
        if ($clean_content) {
            file_put_contents($destination, $clean_content);
        }
    }
    return "Files replaced successfully.";
}
```

4. Checksums for Plugins and Themes
	•	WordPress Plugin and Theme APIs do not provide official checksums. Use these alternatives:
	1.	Manual Hash Calculation:
	•	Compute the hash of plugin or theme files upon download.
	2.	Third-Party Sources:
	•	Use trusted sources like GitHub or VirusTotal for checksum validation.
	3.	Local Cache:
	•	Cache original plugin or theme files for future comparisons.

5. Summary of Flow
	1.	Fetch trusted checksums for WordPress core.
	2.	Calculate local checksums for files.
	3.	Compare local and trusted checksums.
	4.	Log or quarantine tampered files.
	5.	Replace tampered files with clean versions from trusted sources.


## Detailed Implementation Steps

### Phase 1: Foundation (Core Scanner)

#### 1.1 Basic File System Operations
1. Create Core/Scanner directory structure
2. Set up namespace and autoloading
3. Create FileSystemInterface
   - Define basic file operations
   - Add error types
   - Document requirements
4. Implement basic file reading
   - Read file contents
   - Handle permissions
   - Manage errors
5. Add file writing capabilities
   - Safe file writing
   - Atomic operations
   - Backup creation
6. Test file operations
   - Unit tests
   - Error handling tests
   - Permission tests

#### 1.2 Abstract Scanner Base
1. Create AbstractScanner class
   - Basic properties
   - Constructor
   - Interface definition
2. Add file type detection
   - MIME type checking
   - Extension validation
   - Content analysis
3. Implement checksum calculation
   - MD5 generation
   - SHA256 support
   - Result caching
4. Add basic scanning logic
   - File iteration
   - Directory handling
   - Exclusion support
5. Create result structure
   - Status codes
   - Error handling
   - Result formatting
6. Write unit tests
   - Mock file system
   - Test each method
   - Verify error handling

#### 1.3 Malware Scanner Implementation
1. Create MalwareScanner class
   - Extend AbstractScanner
   - Set up properties
   - Define interfaces
2. Add zero-byte detection
   - File size checking
   - Quick scan mode
   - Result caching
3. Implement pattern matching
   - Basic signatures
   - Regular expressions
   - Performance optimization
4. Create quarantine system
   - Safe file isolation
   - Metadata tracking
   - Restore capability
5. Add immediate cleaning
   - Safe file removal
   - Permission handling
   - Logging support
6. Write specific tests
   - Test each feature
   - Performance tests
   - Integration tests

#### 1.4 Integrity Scanner Addition
1. Create IntegrityScanner class
   - Extend AbstractScanner
   - Define properties
   - Set up interfaces
2. Add core file verification
   - Checksum comparison
   - Version checking
   - Update detection
3. Implement JavaScript scanning
   - Content analysis
   - Minification handling
   - Injection detection
4. Add permission verification
   - Permission mapping
   - Security checks
   - Fix recommendations
5. Create repair capability
   - File restoration
   - Permission fixing
   - Backup handling
6. Comprehensive testing
   - Unit tests
   - Integration tests
   - Performance checks

Each micro-step should:
- Be completed in one sitting
- Have clear success criteria
- Be independently testable
- Build on previous steps
- Not break existing functionality

### Phase 2: Monitoring Base
1. Create AbstractMonitor
   - Event logging structure
   - Status tracking
   - Alert system base
   - Performance metrics

2. Implement SystemMonitor
   - File system watching
   - Database monitoring
   - Resource tracking
   - Real-time alerts

### Phase 3: Protection Core
1. Basic Firewall
   - Request filtering
   - IP blocking
   - Basic rules engine
   - Emergency lockdown

2. Login Protection
   - Rate limiting
   - Credential verification
   - Session management
   - Quick blocking

### Phase 4: Cleaning Services
1. FilesCleaner Service
   - Malware removal
   - File restoration
   - Permission fixing
   - Backup management

2. DatabaseCleaner Service
   - Malware detection
   - Content cleaning
   - Table repair
   - Backup/restore

### Phase 5: Cross-Site Protection
1. Site Coordinator
   - Threat sharing
   - Update coordination
   - Resource sharing
   - Status sync

2. API Management
   - Rate limiting
   - Request pooling
   - Error handling
   - Fallback systems

### Phase 6: Testing & Integration
1. Unit Tests
   - Scanner tests
   - Monitor tests
   - Cleaner tests
   - API tests

2. Integration Tests
   - Full system tests
   - Cross-site tests
   - Performance tests
   - Security tests

Each phase delivers working functionality that builds on previous phases. Every component is tested and functional before moving to the next phase.

## Recent Changes

### 2024-01-01
- Refactored malware detection system:
  - Extracted pattern management to ThreatPatternManager class
  - Improved maintainability and extensibility of threat detection
  - Added support for custom malware patterns
  - Prepared for future pattern updates and sharing between sites

### Next Steps
- Implement configuration management system
- Add caching for scan results
- Create pattern update mechanism between sites
- Add resource limit configuration
