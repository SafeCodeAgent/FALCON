# SWE-agent harness

`runner.py` writes SWE-agent instances from the public SusVibes fields, runs
the vendored SWE-agent 1.1.0 with a 200-call limit and a 1,800-second task
deadline, puts each SWE-ReX task container on a Docker bridge without outbound
access, and merges the resulting `.pred` files into SusVibes predictions.

The security check is attached at the submission step by
`av_susvibes/swe_gate.py`. When a submitted patch is insecure, the submission
is cancelled and the counterexample becomes the agent's next observation. If
the check itself fails, the submission is accepted unchanged. Run with
`av-susvibes swe-agent`.
