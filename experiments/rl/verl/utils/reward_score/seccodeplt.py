"""SecCodePLT+ reward entry point for the vendored VeRL dispatcher."""

from reward import compute_score as av_compute_score


def compute_score(solution_str, extra_info=None, safety_ratio=0.0,
                  ut_ratio=0.5, mypy_ratio=0.0, scpd_ratio=0.5,
                  config=None, eval_mode=False):
    return av_compute_score(
        data_source="fengyao1909/seccodeplt_ut",
        solution_str=solution_str,
        extra_info=extra_info,
        config=config,
        eval_mode=eval_mode,
    )
