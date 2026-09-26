"""Deterministic scheduler regressions; no keys, network, Frida, or GUI."""
import _bootstrap  # noqa: F401  (puts app/ on sys.path)
import math
import unittest

from native_analysis import NativeAnalysis, format_analysis


def insight(label="可能需要确认安排"):
    return {"available": True, "question_title": "这句话可能意味着什么？",
            "options": [{"label": label, "probability": .72},
                        {"label": "可能只是确认信息", "probability": .28}],
            "risk_score": 3.5, "action": "先核对范围和时间，再确认下一步"}


def msg(identifier=1, generation=1, who="her", text="明天方便吗", name=None):
    return dict(id=identifier, generation=generation, who=who, text=text, name=name)


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.pending = []
        self.calls = []
        self.delivered = []
        self.failures = 0

        def analyze(turns, **options):
            self.calls.append((turns, options))
            if self.failures:
                self.failures -= 1
                raise RuntimeError("Synthetic failure; must never be displayed")
            return insight()

        self.scheduler = NativeAnalysis(lambda *args: self.delivered.append(args),
                                        analyze_fn=analyze, submit=self.pending.append,
                                        clock=lambda: self.now)

    def snapshot(self, conversation="peer:A", messages=None):
        self.scheduler.on_snapshot(dict(conversation=conversation,
                                        messages=[msg()] if messages is None else messages))

    def finish(self):
        self.pending.pop(0)()
        self.scheduler.tick()

    def test_latest_three_auto_start_single_worker_and_bounded_context(self):
        messages = [msg(i, who="her" if i % 2 == 0 else "me", text=f"示例 {i}")
                    for i in range(18)]
        self.snapshot(messages=messages)
        self.assertEqual(len(self.pending), 1)
        for _ in range(3):
            self.finish()
            self.assertLessEqual(len(self.pending), 1)
            self.now += 2.8
            self.scheduler.tick()
        self.assertEqual([item[0] for item in self.delivered], [16, 14, 12])
        self.assertEqual([call[0][-1][1] for call in self.calls], ["示例 16", "示例 14", "示例 12"])
        self.assertTrue(all(len(call[0]) == 12 for call in self.calls))
        options = self.calls[0][1]
        self.assertEqual(options["timeout"], 40)
        self.assertEqual(options["context"], 12)
        self.assertTrue(options["analysis_only"])
        self.assertEqual((options["jev_provider"], options["jev_model"]), ("typesafe", "jev-latest"))
        self.assertIn("通用沟通", options["relationship"])
        self.snapshot(messages=messages)
        self.assertFalse(self.pending)
        self.assertEqual(len(self.delivered), 3)

    def test_cross_conversation_late_completion_cannot_publish_or_seed_cache(self):
        self.snapshot()
        self.snapshot("peer:B")
        self.assertEqual(len(self.pending), 1)
        self.finish()
        self.assertFalse(self.delivered)
        self.assertFalse(self.scheduler.cache)
        self.assertEqual(len(self.pending), 1)
        self.finish()
        self.assertEqual(len(self.delivered), 1)
        self.snapshot("peer:A")
        self.assertEqual(len(self.pending), 1)

    def test_target_eligibility_keeps_all_preceding_turns_as_context(self):
        messages = [dict(msg(1, text="前文对方问题"), targetEligible=False),
                    dict(msg(2, who="me", text="前文自己的补充"), targetEligible=False),
                    dict(msg(3, text="选中的目标"), targetEligible=True),
                    dict(msg(4, text="未选中的更新消息"), targetEligible=False)]
        self.snapshot(messages=messages)
        self.finish()
        self.assertEqual([item[0] for item in self.delivered], [3])
        self.assertEqual([turn[1] for turn in self.calls[0][0]],
                         ["前文对方问题", "前文自己的补充", "选中的目标"])
        self.assertTrue(all(len(turn) == 3 for turn in self.calls[0][0]))
        self.assertFalse(self.pending)

    def test_clipping_eligible_targets_does_not_promote_older_visible_messages(self):
        older = [dict(msg(i, text=f"旧消息 {i}"), targetEligible=False) for i in range(1, 5)]
        targets = [dict(msg(i, text=f"目标消息 {i}"), targetEligible=True) for i in range(5, 8)]
        self.snapshot(messages=older + targets)
        self.finish()  # Latest target grows and clips remaining targets out.
        self.snapshot(messages=older)
        self.finish()  # Previously scheduled target completes late and is discarded.
        self.assertEqual([item[0] for item in self.delivered], [7])
        self.assertFalse(self.pending)
        for _ in range(5):
            self.now += 10
            self.snapshot(messages=older)
        self.assertFalse(self.pending)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.scheduler.request_counts,
                         {"requestsStarted": 2, "requestsCompleted": 2})

    def test_ineligible_only_snapshot_starts_no_request_and_flags_are_strict(self):
        self.snapshot(messages=[dict(msg(), targetEligible=False)])
        self.assertFalse(self.pending)
        self.assertEqual(self.scheduler.request_counts["requestsStarted"], 0)
        with self.assertRaises(ValueError):
            self.snapshot(messages=[dict(msg(), targetEligible="false")])

    def test_request_counts_include_failed_and_late_calls_but_not_cache_reuse(self):
        self.snapshot()
        self.assertEqual(self.scheduler.request_counts["requestsStarted"], 0)
        self.finish()
        self.assertEqual(self.scheduler.request_counts,
                         {"requestsStarted": 1, "requestsCompleted": 1})
        copied = self.scheduler.request_counts
        copied["requestsStarted"] = 999
        self.snapshot(messages=[msg(9, 2)])
        self.assertFalse(self.pending)
        self.assertEqual(self.scheduler.request_counts["requestsStarted"], 1)
        self.failures = 1
        self.snapshot("peer:B")
        self.finish()
        self.now += 8
        self.scheduler.tick()
        self.now += 45
        self.finish()
        self.assertEqual(self.scheduler.request_counts,
                         {"requestsStarted": 3, "requestsCompleted": 3})

    def test_worker_only_queues_delivery_until_host_tick(self):
        self.snapshot()
        self.pending.pop(0)()
        self.assertFalse(self.delivered)
        self.scheduler.tick()
        self.assertEqual(len(self.delivered), 1)

    def test_pending_delivery_respects_global_interval_without_another_api_request(self):
        attempts = []
        self.scheduler.on_result = lambda *args: attempts.append(args) or False
        self.snapshot()
        self.finish()
        first_receipt = self.scheduler.delivery_receipt(1, 1)
        self.assertFalse(self.scheduler.candidates[0].delivered)
        for now in [.2, .8, 1, 2, 2.799]:
            self.now = now
            self.scheduler.tick()
        self.assertEqual(len(attempts), 1)
        self.now = 2.8
        self.scheduler.tick()
        receipt = self.scheduler.delivery_receipt(1, 1)
        self.assertNotEqual(receipt, first_receipt)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.pending)
        self.assertFalse(self.scheduler.mark_applied(1, 1, first_receipt))
        self.assertTrue(self.scheduler.mark_applied(1, 1, receipt))
        self.now = 10
        self.scheduler.tick()
        self.assertEqual(len(attempts), 2)

    def test_three_cached_results_are_globally_spaced_without_extra_analysis(self):
        messages = [dict(msg(i, text=f"目标 {i}"), logicalId=f"stable-{i}") for i in range(1, 4)]
        self.snapshot(messages=messages)
        for _ in range(3):
            self.finish()
            self.now += 2.8
            self.scheduler.tick()
        self.assertEqual(len(self.calls), 3)
        deliveries = []
        self.scheduler.on_result = lambda *args: deliveries.append((self.now, args))
        self.snapshot("peer:B", [])
        self.snapshot(messages=messages)
        self.assertEqual(len(deliveries), 1)
        start = self.now
        for elapsed in [.2, .8, 1, 2, 2.799]:
            self.now = start + elapsed
            self.scheduler.tick()
            self.assertEqual(len(deliveries), 1)
        self.now = start + 2.8
        self.scheduler.tick()
        self.assertEqual(len(deliveries), 2)
        self.now += 2.8
        self.scheduler.tick()
        self.assertEqual(len(deliveries), 3)
        self.assertTrue(all(second[0] - first[0] >= 2.799999
                            for first, second in zip(deliveries, deliveries[1:])))
        self.assertEqual(len(self.calls), 3)
        self.assertFalse(self.pending)

    def test_host_can_defer_delivery_then_negative_ack_retries_from_cache(self):
        attempts = []
        def deliver(identifier, generation, text):
            attempts.append((identifier, generation, text))
            receipt = self.scheduler.delivery_receipt(identifier, generation)
            self.scheduler.defer_delivery(identifier, generation, receipt, seconds=5)
            return False
        self.scheduler.on_result = deliver
        self.snapshot()
        self.finish()
        receipt = self.scheduler.delivery_receipt(1, 1)
        self.now = 2
        self.scheduler.tick()
        self.assertEqual(len(attempts), 1)
        self.assertTrue(self.scheduler.mark_applied(1, 1, receipt, applied=False))
        self.now = 2.999
        self.scheduler.tick()
        self.assertEqual(len(attempts), 1)
        self.now = 3
        self.scheduler.tick()
        self.assertEqual(len(attempts), 2)
        self.assertEqual(len(self.calls), 1)

    def test_old_receipt_cannot_mark_rebound_or_edited_candidate_delivered(self):
        self.scheduler.on_result = lambda *args: False
        target = dict(msg(1), logicalId="stable-1")
        self.snapshot(messages=[target])
        self.finish()
        receipt = self.scheduler.delivery_receipt(1, 1)
        self.snapshot(messages=[dict(target, generation=2)])
        self.assertFalse(self.scheduler.mark_applied(1, 1, receipt))
        self.assertFalse(self.scheduler.mark_applied(1, 2, receipt))
        rebound_receipt = self.scheduler.delivery_receipt(1, 2)
        self.snapshot(messages=[dict(target, generation=2, text="Edited synthetic text")])
        self.assertFalse(self.scheduler.mark_applied(1, 2, rebound_receipt))
        self.assertFalse(self.scheduler.candidates[0].delivered)

    def test_logical_message_reuses_one_result_after_history_loading_and_view_rebind(self):
        before = dict(msg(1, who="me", text="最初已知前文"), targetEligible=False)
        target = dict(msg(2, text="当前目标"), logicalId="model-100")
        self.snapshot(messages=[before, target])
        self.finish()
        loaded = [dict(msg(-i, text=f"后来加载旧前文 {i}"), logicalId=f"old-{i}",
                       targetEligible=False) for i in range(20, 0, -1)]
        rebound = dict(target, id=500, generation=9)
        self.snapshot(messages=loaded + [before, rebound])
        self.now += 2.8
        self.scheduler.tick()
        self.assertFalse(self.pending)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.delivered[-1][:2], (500, 9))
        self.assertEqual([turn[1] for turn in self.calls[0][0]], ["最初已知前文", "当前目标"])
        self.assertTrue(all(len(turns) <= 12 for turns in self.scheduler._frozen_contexts.values()))

    def test_logical_message_rebind_shares_pending_request_and_only_delivers_new_binding(self):
        target = dict(msg(1), logicalId="model-100")
        self.snapshot(messages=[target])
        self.snapshot(messages=[dict(msg(0, who="me", text="新加载前文"), targetEligible=False),
                                dict(target, id=2, generation=7)])
        self.assertEqual(len(self.pending), 1)
        self.finish()
        self.assertEqual([item[:2] for item in self.delivered], [(2, 7)])
        self.assertFalse(self.pending)
        self.assertEqual(self.scheduler.request_counts["requestsStarted"], 1)

    def test_logical_new_message_text_edit_and_different_peer_each_start_new_context(self):
        target = dict(msg(1, text="原始目标"), logicalId="model-100")
        self.snapshot(messages=[target])
        self.finish()
        edited = dict(target, text="已编辑目标", generation=2)
        before = dict(msg(0, who="me", text="编辑时新前文"), targetEligible=False)
        self.snapshot(messages=[before, edited])
        self.finish()
        self.assertEqual([turn[1] for turn in self.calls[-1][0]], ["编辑时新前文", "已编辑目标"])
        self.snapshot(messages=[before, dict(edited, logicalId="model-101")])
        self.finish()
        self.snapshot("peer:B", [before, edited])
        self.finish()
        self.assertEqual(self.scheduler.request_counts["requestsStarted"], 4)

    def test_context_without_logical_id_still_changes_when_history_changes(self):
        self.snapshot()
        self.finish()
        self.snapshot(messages=[dict(msg(0, who="me", text="后来加载前文"), targetEligible=False),
                                msg(1, generation=2)])
        self.finish()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.calls[-1][0]), 2)

    def test_frozen_logical_context_lru_is_bounded_and_close_clears_it(self):
        for index in range(65):
            self.snapshot(messages=[dict(msg(index, text=f"目标 {index}"), logicalId=f"model-{index}")])
            self.finish()
        self.assertEqual(len(self.scheduler._frozen_contexts), 64)
        self.snapshot(messages=[dict(msg(100, who="me", text="重新选择时的前文"), targetEligible=False),
                                dict(msg(0, text="目标 0"), logicalId="model-0")])
        self.finish()
        self.assertEqual(len(self.calls[-1][0]), 2)
        self.scheduler.close()
        self.assertFalse(self.scheduler._frozen_contexts)

    def test_generation_rebind_and_round_trip_chat_invalidate_inflight(self):
        self.snapshot()
        self.snapshot(messages=[msg(generation=2)])
        self.finish()
        self.assertFalse(self.delivered)
        self.finish()
        self.assertEqual(self.delivered[0][:2], (1, 2))
        self.snapshot("peer:C", [msg(3)])
        self.snapshot("peer:D", [msg(4)])
        self.snapshot("peer:C", [msg(3)])
        self.finish()
        self.assertEqual(len(self.delivered), 1)
        self.assertEqual(len(self.pending), 1)
        self.finish()
        self.now += 2.8
        self.scheduler.tick()
        self.assertEqual(self.delivered[-1][:2], (3, 1))

    def test_timeout_discards_late_result_and_never_overlaps_worker(self):
        self.snapshot()
        self.now = 45
        self.scheduler.tick()
        self.assertTrue(self.scheduler.busy)
        self.assertTrue(self.scheduler.active.expired)
        self.now = 53
        self.scheduler.tick()
        self.assertEqual(len(self.pending), 1)  # Only the original worker exists.
        self.finish()
        self.assertFalse(self.delivered)
        self.assertEqual(len(self.pending), 1)  # Retry starts only after return.
        self.finish()
        self.assertEqual(len(self.delivered), 1)
        self.assertEqual(len(self.calls), 2)

    def test_exact_deadline_completion_rejected_even_without_prior_tick(self):
        self.snapshot()
        self.now = 45
        self.finish()
        self.assertFalse(self.delivered)
        self.assertFalse(self.pending)
        self.now = 52.999
        self.scheduler.tick()
        self.assertFalse(self.pending)
        self.now = 53
        self.scheduler.tick()
        self.assertEqual(len(self.pending), 1)

    def test_failure_retries_once_after_eight_seconds_then_stops(self):
        self.failures = 3
        self.snapshot()
        self.finish()
        self.now = 7.999
        self.scheduler.tick()
        self.assertFalse(self.pending)
        self.now = 8
        self.scheduler.tick()
        self.finish()
        self.now = 200
        self.snapshot()
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.pending)
        self.assertFalse(self.delivered)

    def test_cache_reuses_completed_result_but_isolates_peer_context_and_sender(self):
        self.snapshot(messages=[msg(0, who="me", text="星期一"), msg(1, name="同事甲")])
        self.finish()
        self.snapshot(messages=[msg(7, 2, who="me", text="星期一"), msg(8, 2, name="同事甲")])
        self.now += 2.8
        self.scheduler.tick()
        self.assertFalse(self.pending)
        self.assertEqual(self.delivered[-1][:2], (8, 2))
        self.assertEqual(len(self.calls), 1)
        for peer, context, name in [("peer:B", "星期一", "同事甲"),
                                    ("peer:B", "星期二", "同事甲"),
                                    ("peer:B", "星期二", "同事乙")]:
            self.snapshot(peer, [msg(0, who="me", text=context), msg(1, name=name)])
            self.assertEqual(len(self.pending), 1)
            self.finish()
        self.assertEqual(len(self.calls), 4)

    def test_same_binding_changed_text_and_source_mutation_do_not_reuse(self):
        messages = [msg()]
        self.snapshot(messages=messages)
        messages[0]["text"] = "changed outside scheduler"
        self.finish()
        self.assertEqual(self.calls[0][0][-1][1], "明天方便吗")
        self.snapshot(messages=messages)
        self.assertEqual(len(self.pending), 1)
        self.finish()
        self.assertEqual(len(self.calls), 2)

    def test_cache_lru_is_bounded_and_evicted_entries_can_run_again(self):
        for index in range(65):
            self.snapshot(f"peer:{index}")
            self.finish()
        self.assertEqual(len(self.scheduler.cache), 64)
        self.snapshot("peer:64", [msg(9, 3)])
        self.assertFalse(self.pending)
        self.snapshot("peer:0")
        self.assertEqual(len(self.pending), 1)
        self.finish()
        self.assertEqual(len(self.calls), 66)
        self.assertEqual(len(self.scheduler.cache), 64)

    def test_pause_close_or_unknown_peer_cannot_deliver_pending_results(self):
        self.snapshot()
        self.scheduler.set_enabled(False)
        self.finish()
        self.assertFalse(self.delivered)
        self.snapshot()
        self.assertFalse(self.pending)
        self.scheduler.set_enabled(True)
        self.snapshot()
        self.snapshot("")
        self.finish()
        self.assertFalse(self.delivered)
        self.snapshot()
        self.scheduler.close()
        self.finish()
        self.assertFalse(self.delivered)
        self.assertFalse(self.scheduler.cache)
        self.snapshot()
        self.assertFalse(self.pending)


class FormatTests(unittest.TestCase):
    def test_two_best_probabilities_and_all_sections_fit_budget(self):
        result = insight()
        result["question_title"] = "很长的标题" * 100
        result["action"] = "需要核对的行动" * 100
        result["options"] = [{"label": "甲" * 200, "probability": .2},
                             {"label": "乙" * 200, "probability": .5},
                             {"label": "丙" * 200, "probability": .3}]
        text = format_analysis(result)
        self.assertLessEqual(len(text), 420)
        self.assertIn("50.0%", text)
        self.assertIn("30.0%", text)
        self.assertNotIn("20.0%", text)
        self.assertIn("风险：3.5/10", text)
        self.assertIn("行动：", text)
        self.assertIn("仅供参考", text)

    def test_invalid_values_never_become_probabilities_or_risk_numbers(self):
        for bad in [math.nan, math.inf, -1, 11, True, "0.9", 10**1000]:
            result = insight()
            result["options"] = [{"label": "invalid", "probability": bad}]
            result["risk_score"] = bad
            result["action"] = "NaN"
            text = format_analysis(result)
            self.assertNotIn("%", text)
            self.assertNotIn("/10", text)
            self.assertNotIn("nan", text.lower())
            self.assertNotIn("inf", text.lower())
            self.assertIn("信息不足", text)


if __name__ == "__main__":
    unittest.main()
