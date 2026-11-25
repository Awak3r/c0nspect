import unittest

from summarize_ci import report


def span(start, end, conclusion="success"):
    return {"started_at": f"2026-11-25T09:00:{start:02d}Z", "completed_at": f"2026-11-25T09:00:{end:02d}Z", "conclusion": conclusion}


class SummaryTests(unittest.TestCase):
    def test_attempt_reports_queue_parallel_steps_and_skipped_deploy(self):
        jobs = [
            {"name": "Checks", **span(4, 25)},
            {"name": "Image", **span(9, 27, "failure"), "steps": [
                {"name": "Build (push only main, SHA tag only)", **span(10, 20)},
                {"name": "Smoke image with PostgreSQL, MCP and Chromium", **span(21, 27, "failure")},
                {"name": "Post Restore Go compiler cache", **span(27, 27, "skipped")},
                {"name": "untrusted in summary", **span(1, 2)},
            ]},
            {"name": "Deploy production", "conclusion": "skipped"},
        ]
        text = report(jobs, 1, "2026-11-25T09:00:01Z")
        self.assertIn("first runner started: **3 s**", text)
        self.assertIn("**Checks** | 21 s | success", text)
        self.assertIn("**Image** | 18 s | failure", text)
        self.assertIn("Buildx build / load / push / layer cache | 10 s | success", text)
        self.assertIn("Image smoke (PostgreSQL, MCP, Chromium) | 6 s | failure", text)
        self.assertIn("**Deploy production** | — | skipped", text)
        self.assertNotIn("Save compiler cache", text)
        self.assertNotIn("untrusted", text)

    def test_partial_rerun_does_not_invent_old_job_or_queue_timings(self):
        text = report([{"name": "Checks", "started_at": "bad", "completed_at": None, "conclusion": "failure"}], 2)
        self.assertIn("attempt 2", text)
        self.assertIn("**Checks** | — | failure", text)
        self.assertNotIn("first runner started", text)
        self.assertNotIn("**Image**", text)
