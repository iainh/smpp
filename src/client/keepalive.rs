// ABOUTME: SMPP keep-alive implementation for maintaining long-running client connections
// ABOUTME: Provides periodic enquire_link functionality with configurable timing and failure handling

use std::time::Duration;
use tracing::{debug, warn};

/// Configuration for SMPP keep-alive functionality
///
/// Controls the behavior of periodic enquire_link PDUs sent to maintain
/// session health during long-running connections. The keep-alive mechanism
/// helps detect connection failures and ensures the SMPP session remains active.
///
/// # SMPP Keep-Alive Protocol
///
/// According to SMPP v3.4 specification, enquire_link PDUs should be sent
/// periodically during idle periods to verify the connection is still active.
/// The SMSC should respond with enquire_link_resp within a reasonable time.
///
/// # Example
///
/// ```rust
/// use smpp::client::KeepAliveConfig;
/// use std::time::Duration;
///
/// // Default configuration (30s interval, 10s timeout, 3 max failures)
/// let config = KeepAliveConfig::default();
///
/// // Custom configuration
/// let config = KeepAliveConfig::new(Duration::from_secs(60))
///     .with_timeout(Duration::from_secs(15))
///     .with_max_failures(5);
///
/// // Disabled keep-alive
/// let config = KeepAliveConfig::disabled();
/// ```
#[derive(Debug, Clone)]
pub struct KeepAliveConfig {
    /// Interval between enquire_link PDUs (default: 30 seconds)
    ///
    /// This determines how often keep-alive pings are sent during idle periods.
    /// A typical range is 30-300 seconds. Shorter intervals provide faster failure
    /// detection but generate more network traffic.
    pub interval: Duration,
    
    /// Timeout for enquire_link responses (default: 10 seconds)
    ///
    /// Maximum time to wait for an enquire_link_resp after sending enquire_link.
    /// If no response is received within this time, it's considered a failure.
    /// Should be significantly less than the interval.
    pub timeout: Duration,
    
    /// Maximum consecutive failures before considering connection dead (default: 3)
    ///
    /// Number of consecutive enquire_link failures before the connection is
    /// considered failed. Higher values are more tolerant of temporary network
    /// issues but slower to detect permanent failures.
    pub max_failures: u32,
    
    /// Whether keep-alive is enabled (default: true)
    ///
    /// When false, no enquire_link PDUs will be sent automatically.
    /// Manual enquire_link calls will still work and be tracked.
    pub enabled: bool,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            max_failures: 3,
            enabled: true,
        }
    }
}

impl KeepAliveConfig {
    /// Create a new keep-alive configuration with custom interval
    ///
    /// # Arguments
    ///
    /// * `interval` - Time between enquire_link PDUs
    ///
    /// # Example
    ///
    /// ```rust
    /// use smpp::client::KeepAliveConfig;
    /// use std::time::Duration;
    ///
    /// let config = KeepAliveConfig::new(Duration::from_secs(60));
    /// ```
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            ..Default::default()
        }
    }
    
    /// Set the timeout for enquire_link responses
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for enquire_link_resp
    ///
    /// # Example
    ///
    /// ```rust
    /// use smpp::client::KeepAliveConfig;
    /// use std::time::Duration;
    ///
    /// let config = KeepAliveConfig::default()
    ///     .with_timeout(Duration::from_secs(15));
    /// ```
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Set the maximum consecutive failures before connection is considered dead
    ///
    /// # Arguments
    ///
    /// * `max_failures` - Number of consecutive failures to tolerate
    ///
    /// # Example
    ///
    /// ```rust
    /// use smpp::client::KeepAliveConfig;
    ///
    /// let config = KeepAliveConfig::default()
    ///     .with_max_failures(5);
    /// ```
    pub fn with_max_failures(mut self, max_failures: u32) -> Self {
        self.max_failures = max_failures;
        self
    }
    
    /// Create a disabled keep-alive configuration
    ///
    /// When disabled, no automatic enquire_link PDUs will be sent.
    /// Manual enquire_link calls will still function normally.
    ///
    /// # Example
    ///
    /// ```rust
    /// use smpp::client::KeepAliveConfig;
    ///
    /// let config = KeepAliveConfig::disabled();
    /// assert!(!config.enabled);
    /// ```
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}


/// Status information about keep-alive state
///
/// Provides visibility into the current health and statistics of the
/// keep-alive mechanism. Use this to monitor connection health and
/// troubleshoot issues.
///
/// # Example
///
/// ```rust
/// # use smpp::client::{KeepAliveStatus, KeepAliveConfig, KeepAliveManager};
/// # use std::time::Duration;
/// let manager = KeepAliveManager::new(KeepAliveConfig::default());
/// let status = manager.status();
/// 
/// if status.running {
///     println!("Keep-alive is active");
///     println!("Success rate: {}/{}", status.total_pongs, status.total_pings);
///     
///     if status.consecutive_failures > 0 {
///         println!("Warning: {} consecutive failures", status.consecutive_failures);
///     }
/// } else {
///     println!("Keep-alive is disabled");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct KeepAliveStatus {
    /// Whether keep-alive is currently running
    ///
    /// True if keep-alive is enabled and actively monitoring the connection.
    /// False if disabled or not yet started.
    pub running: bool,
    
    /// Number of consecutive failures
    ///
    /// Count of enquire_link operations that have failed in a row.
    /// Reset to 0 on any successful operation. When this reaches
    /// `max_failures`, the connection is considered dead.
    pub consecutive_failures: u32,
    
    /// Total enquire_link PDUs sent
    ///
    /// Total number of enquire_link PDUs sent since keep-alive started.
    /// Includes both automatic keep-alive pings and manual enquire_link calls.
    pub total_pings: u32,
    
    /// Total successful responses received
    ///
    /// Total number of enquire_link_resp PDUs received successfully.
    /// The success rate is `total_pongs / total_pings`.
    pub total_pongs: u32,
}

/// Manages periodic enquire_link PDUs for SMPP connection health
///
/// The KeepAliveManager provides a timer-based system for tracking when
/// enquire_link PDUs should be sent and monitoring response health.
/// Unlike traditional background-task approaches, this uses a polling
/// model that integrates safely with the existing synchronous client architecture.
///
/// # Integration Pattern
///
/// The manager works by:
/// 1. Client calls `should_ping()` to check if an enquire_link is needed
/// 2. If true, client sends enquire_link and calls `on_ping_sent()`
/// 3. Client calls `on_ping_success()` or `on_ping_failure()` based on result
/// 4. Manager tracks timing and failure counts automatically
///
/// # Example
///
/// ```rust,no_run
/// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
/// # use std::time::Duration;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = KeepAliveConfig::new(Duration::from_secs(30));
/// let mut manager = KeepAliveManager::new(config);
///
/// // In your main loop
/// if manager.should_ping() {
///     manager.on_ping_sent();
///     
///     match send_enquire_link().await {
///         Ok(_) => manager.on_ping_success(),
///         Err(_) => manager.on_ping_failure(),
///     }
/// }
///
/// // Check if connection has failed
/// if manager.is_connection_failed() {
///     // Need to reconnect
/// }
/// # Ok(())
/// # }
/// # async fn send_enquire_link() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
/// ```
#[derive(Debug)]
pub struct KeepAliveManager {
    /// Configuration for keep-alive behavior
    config: KeepAliveConfig,
    
    /// Last time an enquire_link was sent
    last_ping: Option<std::time::Instant>,
    
    /// Number of consecutive failures
    consecutive_failures: u32,
    
    /// Total pings sent
    total_pings: u32,
    
    /// Total successful responses
    total_pongs: u32,
    
    /// Whether keep-alive is enabled
    enabled: bool,
}


impl KeepAliveManager {
    /// Create a new keep-alive manager with the specified configuration
    pub fn new(config: KeepAliveConfig) -> Self {
        Self {
            enabled: config.enabled,
            config,
            last_ping: None,
            consecutive_failures: 0,
            total_pings: 0,
            total_pongs: 0,
        }
    }
    
    /// Enable keep-alive functionality
    ///
    /// Activates automatic timing of enquire_link PDUs. If keep-alive
    /// was previously disabled, this will resume monitoring from the
    /// current time.
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable keep-alive functionality
    ///
    /// Stops automatic timing of enquire_link PDUs. Manual enquire_link
    /// calls will still be tracked for statistics, but `should_ping()`
    /// will always return false.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    
    /// Check if an enquire_link should be sent now
    ///
    /// Returns true if enough time has passed since the last ping,
    /// keep-alive is enabled, and the maximum failure count hasn't
    /// been reached.
    ///
    /// # Returns
    ///
    /// * `true` - An enquire_link should be sent
    /// * `false` - No ping needed (disabled, too soon, or max failures reached)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// let mut manager = KeepAliveManager::new(KeepAliveConfig::default());
    /// 
    /// if manager.should_ping() {
    ///     // Send enquire_link PDU
    ///     manager.on_ping_sent();
    /// }
    /// ```
    pub fn should_ping(&self) -> bool {
        if !self.enabled {
            return false;
        }
        
        if self.consecutive_failures >= self.config.max_failures {
            debug!("Max failures reached, not sending more pings");
            return false;
        }
        
        match self.last_ping {
            None => true, // Never sent a ping
            Some(last) => last.elapsed() >= self.config.interval,
        }
    }
    
    /// Record that an enquire_link was sent
    ///
    /// Call this immediately after successfully sending an enquire_link PDU
    /// to the SMSC. This updates the timing for the next ping and increments
    /// the total ping counter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// let mut manager = KeepAliveManager::new(KeepAliveConfig::default());
    /// 
    /// if manager.should_ping() {
    ///     // Send the enquire_link PDU here
    ///     manager.on_ping_sent();  // Record that it was sent
    /// }
    /// ```
    pub fn on_ping_sent(&mut self) {
        self.last_ping = Some(std::time::Instant::now());
        self.total_pings += 1;
        debug!("Enquire_link sent (total: {})", self.total_pings);
    }
    
    /// Record a successful enquire_link response
    ///
    /// Call this when an enquire_link_resp is received successfully from
    /// the SMSC. This resets the consecutive failure counter and increments
    /// the success counter.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manager = KeepAliveManager::new(KeepAliveConfig::default());
    /// 
    /// // After sending enquire_link and receiving response
    /// match receive_enquire_link_resp().await {
    ///     Ok(_) => manager.on_ping_success(),
    ///     Err(_) => manager.on_ping_failure(),
    /// }
    /// # Ok(())
    /// # }
    /// # async fn receive_enquire_link_resp() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    /// ```
    pub fn on_ping_success(&mut self) {
        self.consecutive_failures = 0;
        self.total_pongs += 1;
        debug!("Enquire_link successful (total: {})", self.total_pongs);
    }
    
    /// Record a failed enquire_link operation
    ///
    /// Call this when an enquire_link times out, receives an error response,
    /// or fails to send. This increments the consecutive failure counter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// let mut manager = KeepAliveManager::new(KeepAliveConfig::default());
    /// 
    /// // After enquire_link fails
    /// manager.on_ping_failure();
    /// 
    /// if manager.is_connection_failed() {
    ///     println!("Connection considered dead");
    /// }
    /// ```
    pub fn on_ping_failure(&mut self) {
        self.consecutive_failures += 1;
        warn!("Enquire_link failed (consecutive failures: {})", self.consecutive_failures);
    }
    
    /// Reset the failure counter
    ///
    /// Call this after successful SMPP operations to reset the consecutive
    /// failure counter, preventing premature connection termination. This
    /// is useful when other operations (like submit_sm) succeed, indicating
    /// the connection is healthy despite enquire_link failures.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manager = KeepAliveManager::new(KeepAliveConfig::default());
    /// 
    /// // After successful SMS send or other operation
    /// if send_sms().await.is_ok() {
    ///     manager.reset_failures();  // Connection is working
    /// }
    /// # Ok(())
    /// # }
    /// # async fn send_sms() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    /// ```
    pub fn reset_failures(&mut self) {
        if self.consecutive_failures > 0 {
            debug!("Resetting {} consecutive failures", self.consecutive_failures);
            self.consecutive_failures = 0;
        }
    }
    
    /// Check if the connection should be considered failed
    ///
    /// Returns true if the number of consecutive failures has exceeded
    /// the configured maximum. When this occurs, the application should
    /// typically close and re-establish the connection.
    ///
    /// # Returns
    ///
    /// * `true` - Connection should be considered failed
    /// * `false` - Connection appears healthy
    ///
    /// # Example
    ///
    /// ```rust
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// let mut manager = KeepAliveManager::new(
    ///     KeepAliveConfig::default().with_max_failures(3)
    /// );
    /// 
    /// // Simulate failures
    /// manager.on_ping_failure();
    /// manager.on_ping_failure();
    /// manager.on_ping_failure();
    /// 
    /// assert!(manager.is_connection_failed());
    /// ```
    pub fn is_connection_failed(&self) -> bool {
        self.consecutive_failures >= self.config.max_failures
    }
    
    /// Get current keep-alive status
    ///
    /// Returns a snapshot of the current keep-alive state including
    /// running status, failure counts, and statistics.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use smpp::client::{KeepAliveConfig, KeepAliveManager};
    /// # use std::time::Duration;
    /// let manager = KeepAliveManager::new(KeepAliveConfig::default());
    /// let status = manager.status();
    /// 
    /// println!("Keep-alive enabled: {}", status.running);
    /// println!("Success rate: {}/{}", status.total_pongs, status.total_pings);
    /// ```
    pub fn status(&self) -> KeepAliveStatus {
        KeepAliveStatus {
            running: self.enabled,
            consecutive_failures: self.consecutive_failures,
            total_pings: self.total_pings,
            total_pongs: self.total_pongs,
        }
    }
    
    /// Check if keep-alive is currently enabled
    ///
    /// Returns true if keep-alive timing is active, false if disabled.
    /// This is equivalent to `status().running`.
    pub fn is_running(&self) -> bool {
        self.enabled
    }
    
    /// Get the configured keep-alive interval
    ///
    /// Returns the time duration between enquire_link PDUs.
    pub fn interval(&self) -> Duration {
        self.config.interval
    }
    
    /// Get the configured timeout
    ///
    /// Returns the maximum time to wait for enquire_link responses.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keep_alive_config_defaults() {
        let config = KeepAliveConfig::default();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.max_failures, 3);
        assert!(config.enabled);
    }

    #[test]
    fn test_keep_alive_config_builder() {
        let config = KeepAliveConfig::new(Duration::from_secs(60))
            .with_timeout(Duration::from_secs(5))
            .with_max_failures(5);
            
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.max_failures, 5);
        assert!(config.enabled);
    }

    #[test]
    fn test_keep_alive_config_disabled() {
        let config = KeepAliveConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_keep_alive_manager_should_ping() {
        let config = KeepAliveConfig::new(Duration::from_millis(100));
        let manager = KeepAliveManager::new(config);
        
        // Should ping initially (no last ping time)
        assert!(manager.should_ping());
        
        // After marking ping sent, should not ping immediately
        let mut manager = manager;
        manager.on_ping_sent();
        assert!(!manager.should_ping());
        
        // Wait and then should ping again
        std::thread::sleep(Duration::from_millis(150));
        assert!(manager.should_ping());
    }

    #[test]
    fn test_keep_alive_failure_tracking() {
        let config = KeepAliveConfig::new(Duration::from_millis(100))
            .with_max_failures(3);
        let mut manager = KeepAliveManager::new(config);
        
        // Initially should be able to ping
        assert!(manager.should_ping());
        assert!(!manager.is_connection_failed());
        
        // Add failures
        manager.on_ping_failure();
        manager.on_ping_failure();
        assert!(!manager.is_connection_failed());
        assert!(manager.should_ping()); // Still under max
        
        // Max failures reached
        manager.on_ping_failure();
        assert!(manager.is_connection_failed());
        assert!(!manager.should_ping()); // Should not ping anymore
        
        // Reset failures
        manager.reset_failures();
        assert!(!manager.is_connection_failed());
        assert!(manager.should_ping());
    }

    #[test] 
    fn test_keep_alive_disabled() {
        let config = KeepAliveConfig::disabled();
        let manager = KeepAliveManager::new(config);
        
        assert!(!manager.is_running());
        assert!(!manager.should_ping());
        
        // Enable it
        let mut manager = manager;
        manager.enable();
        assert!(manager.is_running());
        assert!(manager.should_ping());
    }

    #[test]
    fn test_keep_alive_statistics() {
        let config = KeepAliveConfig::default();
        let mut manager = KeepAliveManager::new(config);
        
        let status = manager.status();
        assert_eq!(status.total_pings, 0);
        assert_eq!(status.total_pongs, 0);
        assert_eq!(status.consecutive_failures, 0);
        
        // Send a ping
        manager.on_ping_sent();
        let status = manager.status();
        assert_eq!(status.total_pings, 1);
        assert_eq!(status.total_pongs, 0);
        
        // Success
        manager.on_ping_success();
        let status = manager.status();
        assert_eq!(status.total_pings, 1);
        assert_eq!(status.total_pongs, 1);
        assert_eq!(status.consecutive_failures, 0);
        
        // Failure
        manager.on_ping_failure();
        let status = manager.status();
        assert_eq!(status.consecutive_failures, 1);
    }
}