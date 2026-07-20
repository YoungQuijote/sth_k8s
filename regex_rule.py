"""业务字段正则映射。

当前对话中具体正则内容被省略，因此这里只保留字段结构占位。
请从现网源码补入完整规则后再用于生产。
"""

INTENT_REGEX = r""
PLAN_REGEX = r""
NEXT_PLAN_REGEX = r""
RE_PLAN_REGEX = r""
SKILL_STEP_RESULT_REGEX = r""
SKIL_RESULT_REGEX = r""
TOOL_CALL_SKILL_COMPLETED_REGEX = r""
TOOL_CALL_BASH_COMPLETED_REGEX = r""
TOOL_CALL_RAG_COMPLETED_REGEX = r""
TIME_4_RUNTIME_QUEUE_ENQUEUED_REGEX = r""
TIME_4_TOOL_CALL_START_BASH_REGEX = r""
TIME_4_TOOL_CALL_START_PYTHON_CN_RAG_SEARCH_REGEX = r""

FIELD_RULES = {
    "intent": INTENT_REGEX,
    "plan": PLAN_REGEX,
    "next_plan": NEXT_PLAN_REGEX,
    "re_plan": RE_PLAN_REGEX,
    "skill_step_result": SKILL_STEP_RESULT_REGEX,
    "skill_result": SKIL_RESULT_REGEX,
    "tool_call_skill_completed": TOOL_CALL_SKILL_COMPLETED_REGEX,
    "tool_call_bash_completed": TOOL_CALL_BASH_COMPLETED_REGEX,
    "tool_call_rag_completed": TOOL_CALL_RAG_COMPLETED_REGEX,
    "time_runtime_queue": TIME_4_RUNTIME_QUEUE_ENQUEUED_REGEX,
    "time_bash_start": TIME_4_TOOL_CALL_START_BASH_REGEX,
    "time_python_rag_start": TIME_4_TOOL_CALL_START_PYTHON_CN_RAG_SEARCH_REGEX,
}
