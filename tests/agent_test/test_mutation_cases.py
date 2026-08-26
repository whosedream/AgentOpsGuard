from .mutation_cases import (
    DANGEROUS_CMDS,
    gen_all_mutation_cases,
    gen_dangerous_command_cases,
)


def test_dangerous_tool_cases_preserve_the_command_for_policy_evaluation():
    tool_cases = [case for case in gen_dangerous_command_cases() if case.tool_name]

    assert len(tool_cases) == len(DANGEROUS_CMDS)
    assert [case.command for case in tool_cases] == DANGEROUS_CMDS


def test_mutation_generation_is_repeatable_within_one_process():
    assert gen_all_mutation_cases() == gen_all_mutation_cases()
