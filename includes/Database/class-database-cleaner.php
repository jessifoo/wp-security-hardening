namespace WP_Security\Database;

use WP_Security\Core\Logger\LoggerInterface;

class DatabaseCleaner {
    private LoggerInterface $logger;
    private array $patterns;
    
    public function __construct(LoggerInterface $logger) {
        $this->logger = $logger;
        $this->patterns = $this->loadPatterns();
    }
    
    private function loadPatterns(): array {
        return apply_filters('wp_security_malware_patterns', [
            'eval\s*\(.*\)',
            'base64_decode\s*\(.*\)',
            '<\?php'
        ]);
    }
    
    public function cleanTable(string $table): array {
        global $wpdb;
        
        if (!$this->isValidTable($table)) {
            throw new \InvalidArgumentException('Invalid table name');
        }
        
        $cleaned = [];
        $columns = $this->getTextColumns($table);
        
        foreach ($columns as $column) {
            foreach ($this->patterns as $pattern) {
                $results = $wpdb->get_results($wpdb->prepare(
                    "SELECT * FROM {$table} WHERE {$column} REGEXP %s",
                    $pattern
                ));
                
                foreach ($results as $row) {
                    $cleaned[] = $this->cleanAndUpdateRow($table, $row, $column);
                    $this->logger->info('Cleaned malicious content', [
                        'table' => $table,
                        'column' => $column,
                        'pattern' => $pattern
                    ]);
                }
            }
        }
        
        return $cleaned;
    }
    
    private function isValidTable(string $table): bool {
        global $wpdb;
        return in_array($table, $wpdb->tables, true);
    }
} 
