//! Agentic runtime smoke tests.

#[cfg(test)]
mod smoke_tests {
    use crate::agentic::AgenticRuntime;

    #[tokio::test]
    async fn test_agent_lifecycle_smoke() {
        let runtime = AgenticRuntime::new();
        runtime.register_agent("test-agent", "test", None).await;

        let llm = runtime
            .track_llm_call(
                "test-agent",
                "openai",
                "gpt-4",
                100,
                50,
                Some("hello".to_string()),
                false,
                vec![],
            )
            .await;
        assert!(llm.total_tokens > 0);

        let stats = runtime.get_agent_stats("test-agent").await;
        assert!(stats.is_some());
    }

    #[tokio::test]
    async fn test_memory_verify_smoke() {
        let runtime = AgenticRuntime::new();
        runtime.register_agent("mem-agent", "test", None).await;
        runtime
            .protect_memory("mem-agent", "system_prompt", "You are helpful")
            .await;

        let verified = runtime
            .verify_memory("mem-agent", "system_prompt", "You are helpful")
            .await;
        assert!(verified.verified);
    }
}
