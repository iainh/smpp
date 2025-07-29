// ABOUTME: SMPP v5.0 flow control and congestion management for adaptive rate limiting
// ABOUTME: Implements smart algorithms that respond to server congestion states and error conditions

use crate::datatypes::CommandStatus;
use std::time::{Duration, Instant};

/// SMPP v5.0 flow control manager for adaptive rate limiting
///
/// Monitors server congestion states and implements intelligent backoff algorithms
/// to optimize message throughput while respecting server capacity limits.
#[derive(Debug)]
pub struct FlowControlManager {
    /// Current congestion state (0-100, where 100 = fully congested)
    congestion_state: Option<u8>,
    /// Current rate limit (messages per second)
    current_rate_limit: f64,
    /// Base rate limit when no congestion
    base_rate_limit: f64,
    /// Minimum rate limit (never go below this)
    min_rate_limit: f64,
    /// Maximum rate limit (never exceed this)
    max_rate_limit: f64,
    /// Last time congestion state was updated
    last_congestion_update: Option<Instant>,
    /// Statistics for monitoring and debugging
    statistics: FlowControlStatistics,
    /// Configuration parameters
    config: FlowControlConfig,
}

/// Configuration for flow control behavior
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    /// How aggressively to reduce rate when congested (0.0-1.0)
    pub congestion_sensitivity: f64,
    /// How quickly to recover rate when congestion clears (0.0-1.0)
    pub recovery_rate: f64,
    /// How long to wait before assuming congestion cleared if no updates
    pub congestion_timeout: Duration,
    /// Minimum delay between rate adjustments
    pub adjustment_interval: Duration,
    /// Enable adaptive behavior based on error responses
    pub enable_error_based_adaptation: bool,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            congestion_sensitivity: 0.8, // Aggressive congestion response
            recovery_rate: 0.1, // Conservative recovery
            congestion_timeout: Duration::from_secs(60), // 1 minute timeout
            adjustment_interval: Duration::from_secs(5), // 5 second intervals
            enable_error_based_adaptation: true,
        }
    }
}

/// Statistics for flow control monitoring
#[derive(Debug, Clone, Default)]
pub struct FlowControlStatistics {
    /// Total number of rate adjustments made
    pub total_adjustments: u64,
    /// Number of times rate was reduced due to congestion
    pub congestion_reductions: u64,
    /// Number of times rate was increased during recovery
    pub recovery_increases: u64,
    /// Number of error-based adjustments
    pub error_adjustments: u64,
    /// Current effective rate (messages/second)
    pub effective_rate: f64,
    /// Time of last adjustment
    pub last_adjustment: Option<Instant>,
    /// Peak rate achieved
    pub peak_rate: f64,
    /// Minimum rate experienced
    pub minimum_rate: f64,
}

impl FlowControlManager {
    /// Create a new flow control manager with specified rate limits
    pub fn new(base_rate_limit: f64, max_rate_limit: f64, min_rate_limit: f64) -> Self {
        let mut statistics = FlowControlStatistics::default();
        statistics.effective_rate = base_rate_limit;
        statistics.peak_rate = base_rate_limit;
        statistics.minimum_rate = base_rate_limit;

        Self {
            congestion_state: None,
            current_rate_limit: base_rate_limit,
            base_rate_limit,
            min_rate_limit,
            max_rate_limit,
            last_congestion_update: None,
            statistics,
            config: FlowControlConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        base_rate_limit: f64,
        max_rate_limit: f64,
        min_rate_limit: f64,
        config: FlowControlConfig,
    ) -> Self {
        let mut manager = Self::new(base_rate_limit, max_rate_limit, min_rate_limit);
        manager.config = config;
        manager
    }

    /// Update congestion state from server response
    pub fn update_congestion_state(&mut self, congestion_state: u8) {
        let now = Instant::now();
        let previous_state = self.congestion_state;
        
        self.congestion_state = Some(congestion_state);
        self.last_congestion_update = Some(now);

        // Only adjust if enough time has passed since last adjustment
        if let Some(last_adj) = self.statistics.last_adjustment {
            if now.duration_since(last_adj) < self.config.adjustment_interval {
                return;
            }
        }

        // Calculate new rate based on congestion level
        let congestion_factor = (100 - congestion_state) as f64 / 100.0;
        let target_rate = self.base_rate_limit * congestion_factor;
        
        // Apply congestion sensitivity
        let adjustment_magnitude = if congestion_state > 0 {
            // Reduce rate aggressively when congested
            self.config.congestion_sensitivity
        } else {
            // Recover slowly when congestion clears
            self.config.recovery_rate
        };

        let new_rate = if target_rate < self.current_rate_limit {
            // Reducing rate due to congestion
            let reduction = (self.current_rate_limit - target_rate) * adjustment_magnitude;
            self.current_rate_limit - reduction
        } else {
            // Increasing rate as congestion clears
            let increase = (target_rate - self.current_rate_limit) * adjustment_magnitude;
            self.current_rate_limit + increase
        };

        self.set_rate_limit(new_rate.clamp(self.min_rate_limit, self.max_rate_limit));

        // Update statistics
        if previous_state.is_some() {
            if congestion_state > previous_state.unwrap() {
                self.statistics.congestion_reductions += 1;
            } else if congestion_state < previous_state.unwrap() {
                self.statistics.recovery_increases += 1;
            }
        }
    }

    /// Handle error response and potentially adjust rate
    pub fn handle_error_response(&mut self, error: CommandStatus) {
        if !self.config.enable_error_based_adaptation {
            return;
        }

        let now = Instant::now();
        
        // Only adjust for throttling-related errors
        if !error.is_throttling_related() {
            return;
        }

        // Check if enough time has passed since last adjustment
        if let Some(last_adj) = self.statistics.last_adjustment {
            if now.duration_since(last_adj) < self.config.adjustment_interval {
                return;
            }
        }

        // Reduce rate based on error severity
        let reduction_factor = match error {
            CommandStatus::CongestionStateRejected => 0.7, // 30% reduction
            CommandStatus::MessageThrottled => 0.8, // 20% reduction  
            CommandStatus::ThrottlingError => 0.9, // 10% reduction
            _ => 1.0, // No reduction
        };

        let new_rate = self.current_rate_limit * reduction_factor;
        self.set_rate_limit(new_rate.clamp(self.min_rate_limit, self.max_rate_limit));
        
        self.statistics.error_adjustments += 1;
    }

    /// Get current rate limit (messages per second)
    pub fn current_rate_limit(&self) -> f64 {
        self.current_rate_limit
    }

    /// Get delay between messages based on current rate
    pub fn message_delay(&self) -> Duration {
        if self.current_rate_limit <= 0.0 {
            Duration::from_secs(1) // Default 1 second if rate is zero
        } else {
            Duration::from_secs_f64(1.0 / self.current_rate_limit)
        }
    }

    /// Get current congestion state
    pub fn congestion_state(&self) -> Option<u8> {
        // Check if congestion state has timed out
        if let (Some(state), Some(last_update)) = (self.congestion_state, self.last_congestion_update) {
            if last_update.elapsed() > self.config.congestion_timeout {
                return None; // Congestion state has expired
            }
            Some(state)
        } else {
            None
        }
    }

    /// Check if server is currently congested
    pub fn is_congested(&self) -> bool {
        self.congestion_state().map_or(false, |state| state > 20) // > 20% congestion
    }

    /// Get flow control statistics
    pub fn statistics(&self) -> &FlowControlStatistics {
        &self.statistics
    }

    /// Reset statistics
    pub fn reset_statistics(&mut self) {
        self.statistics = FlowControlStatistics::default();
        self.statistics.effective_rate = self.current_rate_limit;
        self.statistics.peak_rate = self.current_rate_limit;
        self.statistics.minimum_rate = self.current_rate_limit;
    }

    /// Get recommended action based on current state
    pub fn recommended_action(&self) -> FlowControlAction {
        if let Some(congestion) = self.congestion_state() {
            match congestion {
                0..=10 => FlowControlAction::IncreaseRate,
                11..=30 => FlowControlAction::MaintainRate,
                31..=60 => FlowControlAction::ReduceRate,
                61..=80 => FlowControlAction::ReduceRateSignificantly,
                81..=100 => FlowControlAction::MinimizeRate,
                _ => FlowControlAction::MinimizeRate, // Handle values > 100 (shouldn't happen but be safe)
            }
        } else {
            // No congestion info, maintain current rate
            FlowControlAction::MaintainRate
        }
    }

    /// Set new rate limit and update statistics
    fn set_rate_limit(&mut self, new_rate: f64) {
        self.current_rate_limit = new_rate;
        self.statistics.effective_rate = new_rate;
        self.statistics.last_adjustment = Some(Instant::now());
        self.statistics.total_adjustments += 1;
        
        if new_rate > self.statistics.peak_rate {
            self.statistics.peak_rate = new_rate;
        }
        if new_rate < self.statistics.minimum_rate {
            self.statistics.minimum_rate = new_rate;
        }
    }
}

/// Recommended flow control actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControlAction {
    /// Increase message rate (low congestion)
    IncreaseRate,
    /// Maintain current rate (moderate congestion)
    MaintainRate,
    /// Reduce message rate (high congestion)
    ReduceRate,
    /// Significantly reduce rate (very high congestion)
    ReduceRateSignificantly,
    /// Use minimum rate (critical congestion)
    MinimizeRate,
}

impl FlowControlAction {
    /// Get human-readable description of the action
    pub fn description(&self) -> &'static str {
        match self {
            FlowControlAction::IncreaseRate => "Increase message rate - low server congestion",
            FlowControlAction::MaintainRate => "Maintain current rate - moderate congestion",
            FlowControlAction::ReduceRate => "Reduce message rate - high server congestion",
            FlowControlAction::ReduceRateSignificantly => "Significantly reduce rate - very high congestion",
            FlowControlAction::MinimizeRate => "Use minimum rate - critical server congestion",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_control_manager_creation() {
        let manager = FlowControlManager::new(10.0, 50.0, 1.0);
        assert_eq!(manager.current_rate_limit(), 10.0);
        assert_eq!(manager.congestion_state(), None);
        assert!(!manager.is_congested());
    }

    #[test]
    fn test_congestion_state_update() {
        let mut manager = FlowControlManager::new(10.0, 50.0, 1.0);
        
        // Test congestion response
        manager.update_congestion_state(50); // 50% congestion
        assert_eq!(manager.congestion_state(), Some(50));
        assert!(manager.is_congested());
        assert!(manager.current_rate_limit() < 10.0); // Rate should be reduced
    }

    #[test]
    fn test_error_based_adjustment() {
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        let initial_rate = manager.current_rate_limit();
        
        manager.handle_error_response(CommandStatus::CongestionStateRejected);
        assert!(manager.current_rate_limit() < initial_rate);
        assert_eq!(manager.statistics().error_adjustments, 1);
    }

    #[test]
    fn test_rate_limits_respected() {
        let mut manager = FlowControlManager::new(10.0, 50.0, 1.0);
        
        // Test minimum limit
        manager.update_congestion_state(100); // Maximum congestion
        assert!(manager.current_rate_limit() >= 1.0);
        
        // Test maximum limit
        manager.update_congestion_state(0); // No congestion
        // Allow multiple adjustments to test max limit
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(10));
            manager.update_congestion_state(0);
        }
        assert!(manager.current_rate_limit() <= 50.0);
    }

    #[test]
    fn test_message_delay_calculation() {
        let manager = FlowControlManager::new(10.0, 50.0, 1.0);
        let delay = manager.message_delay();
        assert_eq!(delay, Duration::from_millis(100)); // 1/10 second = 100ms
    }

    #[test]
    fn test_recommended_actions() {
        let mut manager = FlowControlManager::new(10.0, 50.0, 1.0);
        
        manager.update_congestion_state(5);
        assert_eq!(manager.recommended_action(), FlowControlAction::IncreaseRate);
        
        manager.update_congestion_state(50);
        assert_eq!(manager.recommended_action(), FlowControlAction::ReduceRate);
        
        manager.update_congestion_state(90);
        assert_eq!(manager.recommended_action(), FlowControlAction::MinimizeRate);
    }

    #[test]
    fn test_congestion_timeout() {
        let mut config = FlowControlConfig::default();
        config.congestion_timeout = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        
        manager.update_congestion_state(50);
        assert_eq!(manager.congestion_state(), Some(50));
        
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(manager.congestion_state(), None); // Should timeout
    }

    #[test]
    fn test_statistics_tracking() {
        let mut config = FlowControlConfig::default();
        config.adjustment_interval = Duration::from_millis(1);
        
        let mut manager = FlowControlManager::with_config(10.0, 50.0, 1.0, config);
        
        manager.update_congestion_state(50);
        std::thread::sleep(Duration::from_millis(5));
        manager.handle_error_response(CommandStatus::MessageThrottled);
        
        let stats = manager.statistics();
        assert!(stats.total_adjustments > 0);
        assert!(stats.error_adjustments > 0);
        assert!(stats.effective_rate < 10.0);
    }
}