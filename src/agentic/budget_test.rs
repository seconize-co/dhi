//! Unit tests for Budget Controller

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_controller() -> BudgetController {
        BudgetController::new()
    }

    // ==================== Basic Budget Checks ====================

    #[test]
    fn test_new_agent_under_budget() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        
        let result = bc.check_budget("agent-1", 10.0);
        assert!(result.allowed, "Should allow spending under budget");
        assert!(!result.exceeded, "Should not be exceeded");
    }

    #[test]
    fn test_agent_over_budget() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 10.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 8.0);
        
        let result = bc.check_budget("agent-1", 5.0);
        assert!(!result.allowed, "Should not allow spending over budget");
        assert!(result.exceeded, "Should be exceeded");
    }

    #[test]
    fn test_exact_budget_limit() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 10.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 10.0);
        
        let result = bc.check_budget("agent-1", 0.01);
        assert!(!result.allowed, "Should not allow any more spending at limit");
    }

    // ==================== Global Budget ====================

    #[test]
    fn test_global_budget_check() {
        let mut bc = budget_controller();
        bc.set_global_budget(100.0, BudgetPeriod::Daily);
        
        let result = bc.check_budget("any-agent", 50.0);
        assert!(result.allowed, "Should allow under global budget");
    }

    #[test]
    fn test_global_budget_exceeded() {
        let mut bc = budget_controller();
        bc.set_global_budget(100.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 60.0);
        bc.record_spend("agent-2", 30.0);
        
        let result = bc.check_budget("agent-3", 20.0);
        assert!(!result.allowed, "Should block when global budget exceeded");
    }

    // ==================== Agent + Global Budget ====================

    #[test]
    fn test_agent_under_but_global_over() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 50.0, BudgetPeriod::Daily);
        bc.set_global_budget(100.0, BudgetPeriod::Daily);
        
        // Other agents spent a lot
        bc.record_spend("agent-2", 90.0);
        
        // Agent-1 is under its own budget but global is near limit
        let result = bc.check_budget("agent-1", 20.0);
        assert!(!result.allowed, "Should block due to global budget");
    }

    #[test]
    fn test_agent_over_but_global_under() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 10.0, BudgetPeriod::Daily);
        bc.set_global_budget(1000.0, BudgetPeriod::Daily);
        
        bc.record_spend("agent-1", 10.0);
        
        let result = bc.check_budget("agent-1", 5.0);
        assert!(!result.allowed, "Should block due to agent budget");
    }

    // ==================== Budget Periods ====================

    #[test]
    fn test_daily_budget() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 10.0, BudgetPeriod::Daily);
        
        let stats = bc.get_budget_stats("agent-1");
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.period, BudgetPeriod::Daily);
    }

    #[test]
    fn test_monthly_budget() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 300.0, BudgetPeriod::Monthly);
        
        let stats = bc.get_budget_stats("agent-1");
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.period, BudgetPeriod::Monthly);
    }

    // ==================== Spending Recording ====================

    #[test]
    fn test_record_spend() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        
        bc.record_spend("agent-1", 25.0);
        bc.record_spend("agent-1", 15.0);
        
        let stats = bc.get_budget_stats("agent-1").unwrap();
        assert_eq!(stats.spent, 40.0);
        assert_eq!(stats.remaining, 60.0);
    }

    #[test]
    fn test_record_spend_no_budget() {
        let mut bc = budget_controller();
        
        // Should not panic even without budget set
        bc.record_spend("unknown-agent", 10.0);
    }

    // ==================== Budget Stats ====================

    #[test]
    fn test_budget_stats() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 30.0);
        
        let stats = bc.get_budget_stats("agent-1").unwrap();
        assert_eq!(stats.limit, 100.0);
        assert_eq!(stats.spent, 30.0);
        assert_eq!(stats.remaining, 70.0);
        assert!((stats.utilization - 0.30).abs() < 0.01);
    }

    #[test]
    fn test_budget_stats_unknown_agent() {
        let bc = budget_controller();
        let stats = bc.get_budget_stats("unknown");
        assert!(stats.is_none());
    }

    // ==================== Budget Warnings ====================

    #[test]
    fn test_warning_at_80_percent() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 80.0);
        
        let result = bc.check_budget("agent-1", 5.0);
        assert!(result.allowed, "Should still allow at 80%");
        assert!(result.warning.is_some(), "Should have warning at 80%");
    }

    #[test]
    fn test_warning_at_90_percent() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 90.0);
        
        let result = bc.check_budget("agent-1", 5.0);
        assert!(result.allowed, "Should still allow at 90%");
        assert!(result.warning.is_some(), "Should have warning at 90%");
    }

    // ==================== Multiple Agents ====================

    #[test]
    fn test_multiple_agents_independent() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 50.0, BudgetPeriod::Daily);
        bc.set_agent_budget("agent-2", 100.0, BudgetPeriod::Daily);
        
        bc.record_spend("agent-1", 50.0);
        
        let result1 = bc.check_budget("agent-1", 1.0);
        let result2 = bc.check_budget("agent-2", 50.0);
        
        assert!(!result1.allowed, "Agent-1 should be blocked");
        assert!(result2.allowed, "Agent-2 should still have budget");
    }

    // ==================== Cost Estimation ====================

    #[test]
    fn test_estimate_llm_cost_gpt4() {
        let cost = estimate_llm_cost("gpt-4", 1000, 500);
        // GPT-4: $0.03/1K input, $0.06/1K output
        let expected = (1000.0 * 0.03 / 1000.0) + (500.0 * 0.06 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_estimate_llm_cost_gpt4o() {
        let cost = estimate_llm_cost("gpt-4o", 1000, 500);
        // GPT-4o: $0.005/1K input, $0.015/1K output
        let expected = (1000.0 * 0.005 / 1000.0) + (500.0 * 0.015 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_estimate_llm_cost_claude() {
        let cost = estimate_llm_cost("claude-3-opus", 1000, 500);
        // Claude Opus: $0.015/1K input, $0.075/1K output
        let expected = (1000.0 * 0.015 / 1000.0) + (500.0 * 0.075 / 1000.0);
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn test_estimate_llm_cost_unknown_model() {
        let cost = estimate_llm_cost("unknown-model", 1000, 500);
        // Should use default pricing
        assert!(cost > 0.0);
    }

    // ==================== Budget Reset ====================

    #[test]
    fn test_reset_budget() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 80.0);
        
        bc.reset_budget("agent-1");
        
        let stats = bc.get_budget_stats("agent-1").unwrap();
        assert_eq!(stats.spent, 0.0);
    }

    #[test]
    fn test_reset_all_budgets() {
        let mut bc = budget_controller();
        bc.set_agent_budget("agent-1", 100.0, BudgetPeriod::Daily);
        bc.set_agent_budget("agent-2", 100.0, BudgetPeriod::Daily);
        bc.record_spend("agent-1", 50.0);
        bc.record_spend("agent-2", 60.0);
        
        bc.reset_all();
        
        let stats1 = bc.get_budget_stats("agent-1").unwrap();
        let stats2 = bc.get_budget_stats("agent-2").unwrap();
        assert_eq!(stats1.spent, 0.0);
        assert_eq!(stats2.spent, 0.0);
    }
}
