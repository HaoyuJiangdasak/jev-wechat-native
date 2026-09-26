# -*- coding: utf-8 -*-
"""并行调度改动后的契约测试（离线、无 key、无网络、无 Frida）。"""
import _bootstrap  # noqa: F401  (puts app/ on sys.path)
import unittest

from native_analysis import MAX_CANDIDATES, MAX_WORKERS, NativeAnalysis

# 候选数上限（3）比 worker 池（4）小，所以实际并发就是 3。
CONCURRENT = min(MAX_CANDIDATES, MAX_WORKERS)


def insight(label="可能需要确认安排"):
    return {"available": True, "question_title": "这句话可能意味着什么？",
            "options": [{"label": label, "probability": .72},
                        {"label": "可能只是确认信息", "probability": .28}],
            "risk_score": 3.5, "action": "先核对范围和时间，再确认下一步"}


def msg(identifier=1, generation=1, who="her", text="明天方便吗", name=None):
    return dict(id=identifier, generation=generation, who=who, text=text, name=name)


class ParallelWorkerTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.pending = []
        self.calls = []
        self.delivered = []

        def analyze(turns, **options):
            self.calls.append((turns, options))
            return insight()

        self.scheduler = NativeAnalysis(lambda *args: self.delivered.append(args),
                                        analyze_fn=analyze, submit=self.pending.append,
                                        clock=lambda: self.now)

    def snapshot(self, conversation="peer:A", messages=None):
        self.scheduler.on_snapshot(dict(conversation=conversation,
                                        messages=[msg()] if messages is None else messages))

    def test_three_targets_start_concurrently_not_one_at_a_time(self):
        """三条目标消息应当同时开跑，而不是一张卡一张卡排队。"""
        messages = [msg(i, who="her" if i % 2 == 0 else "me", text=f"示例 {i}")
                    for i in range(18)]
        self.snapshot(messages=messages)
        # 旧行为这里是 1（单 worker 排队）；新行为三条一起放出去。
        self.assertEqual(len(self.pending), CONCURRENT)
        self.assertGreater(CONCURRENT, 1)

    def test_worker_pool_is_bounded(self):
        """池子有上限，不会因为消息多就无限开线程。"""
        messages = [msg(i, who="her", text=f"示例 {i}") for i in range(30)]
        self.snapshot(messages=messages)
        self.assertLessEqual(len(self.pending), CONCURRENT)

    def test_each_worker_gets_one_distinct_target(self):
        """每个 worker 盯的是不同的那一条消息，不能重复分析同一条。"""
        messages = [msg(i, who="her", text=f"示例 {i}") for i in range(6)]
        self.snapshot(messages=messages)
        targets = [call[0][-1][1] for call in self.calls]
        self.assertEqual(len(targets), len(set(targets)))

    def test_all_three_results_deliver_after_parallel_completion(self):
        """三条并行跑完后，三张卡都要交付出来。"""
        messages = [msg(i, who="her" if i % 2 == 0 else "me", text=f"示例 {i}")
                    for i in range(18)]
        self.snapshot(messages=messages)
        jobs = list(self.pending)
        self.pending.clear()
        for job in jobs:
            job()  # 三个 worker 全部返回
        for _ in range(12):
            self.scheduler.tick()
            self.now += 0.5
        self.assertEqual(len(self.delivered), CONCURRENT)

    def test_interleaved_completion_does_not_cross_publish(self):
        """并行完成的顺序被打乱，也不能串台或重复交付。"""
        messages = [msg(i, who="her" if i % 2 == 0 else "me", text=f"示例 {i}")
                    for i in range(18)]
        self.snapshot(messages=messages)
        jobs = list(self.pending)
        self.pending.clear()
        # 倒序完成：最后排的那条先回来
        for job in reversed(jobs):
            job()
        for _ in range(8):
            self.scheduler.tick()
            self.now += 0.5
        ids = [item[0] for item in self.delivered]
        self.assertEqual(len(ids), len(set(ids)))  # 不重复

    def test_cache_prevents_extra_requests_across_workers(self):
        """已缓存的结果不该再发请求。"""
        messages = [msg(i, who="her" if i % 2 == 0 else "me", text=f"示例 {i}")
                    for i in range(18)]
        self.snapshot(messages=messages)
        jobs = list(self.pending)
        self.pending.clear()
        for job in jobs:
            job()
        for _ in range(12):
            self.scheduler.tick()
            self.now += 0.5
        started = self.scheduler.request_counts["requestsStarted"]
        self.assertEqual(started, CONCURRENT)  # 每条目标各跑一次
        self.snapshot(messages=messages)  # 同样的快照重来一次
        self.scheduler.tick()
        self.assertEqual(self.scheduler.request_counts["requestsStarted"], started)
        self.assertFalse(self.pending)  # 没有新请求排队

    def test_busy_reflects_pool_state(self):
        self.snapshot()
        self.assertTrue(self.scheduler.busy)
        self.pending.pop(0)()
        self.scheduler.tick()
        self.assertFalse(self.scheduler.busy)

    def test_close_clears_pool(self):
        """close() 之后候选、缓存都清空，在途的作业不再交付。

        busy 仍会是 True，直到在途作业真的返回——线程杀不掉，这是原本就有的契约
        （busy 的 docstring：includes expired/stale workers until their execution
        actually finishes）。关键是它们回来后不会再交付任何东西。
        """
        messages = [msg(i, who="her", text=f"示例 {i}") for i in range(6)]
        self.snapshot(messages=messages)
        jobs = list(self.pending)
        self.pending.clear()
        self.scheduler.close()
        self.assertFalse(self.scheduler.candidates)
        self.assertFalse(self.scheduler.cache)
        self.assertFalse(self.scheduler.enabled)
        for job in jobs:  # 在途作业返回
            job()
        for _ in range(8):
            self.scheduler.tick()
            self.now += 0.5
        self.assertFalse(self.delivered)  # 一个字都不该交付出去


if __name__ == "__main__":
    unittest.main(verbosity=2)
