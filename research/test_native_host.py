"""Offline lifecycle tests: no Frida import, Windows calls, API, or GUI."""
import json
import unittest

from native_host import NativeHost, TargetSelectionError, safe_stats, select_window
from native_analysis import NativeAnalysis


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def wait(self, seconds):
        self.now += seconds


class Script:
    def __init__(self, stop_after=1, initialization_error=False, ack=True):
        self.exports_sync = self
        self.callback = None
        self.stop_after = stop_after
        self.initialization_error = initialization_error
        self.calls = []
        self.unloaded = False
        self.ack = ack

    def on(self, event, callback):
        self.callback = callback

    def emit(self, payload):
        self.callback({"type": "send", "payload": payload}, None)

    def load(self):
        if self.initialization_error:
            self.callback({"type": "error", "description": "SECRET_ERROR_BODY",
                           "stack": "SECRET_STACK"}, None)
            return
        self.emit({"event": "ready", "guiThread": 100})
        self.emit({"event": "snapshot", "snapshot": {"conversation": "old-peer", "messages": []}})
        self.emit({"event": "snapshot", "snapshot": {"conversation": "SECRET_PEER", "messages": [
            {"id": "view", "generation": 8, "who": "her", "text": "SECRET_SYNTHETIC_TEXT"}]}})
        self.emit({"event": "stats", "stats": {"bindings": 3, "applied": 1,
                    "errors": 0, "text": "SECRET_STATS_BODY", "SECRET_KEY": 32,
                    "chatEpoch": "SECRET_WRONG_TYPE", "restored": True}})

    def annotate(self, identifier, generation, text, delivery_id):
        self.calls.append(("annotate", identifier, generation, text, delivery_id))
        if self.ack is not None:
            self.emit({"event": "annotation_result", "deliveryId": delivery_id, "applied": self.ack})
        return True

    def heartbeat(self):
        self.calls.append(("heartbeat",))

    def stop(self):
        self.calls.append(("stop",))
        attempts = sum(call[0] == "stop" for call in self.calls)
        if self.stop_after and attempts >= self.stop_after:
            self.emit({"event": "stopped", "unresolved": 0, "stats": {"restored": 1}})
        else:
            self.emit({"event": "stop_pending", "unresolved": 1, "stats": {"restored": 0}})
        return True  # True is not enough to establish restoration.

    def unload(self):
        self.unloaded = True
        self.calls.append(("unload",))


class Session:
    def __init__(self, script):
        self.script = script
        self.detached = False

    def on(self, event, callback):
        self.callback = callback

    def create_script(self, source):
        return self.script

    def detach(self):
        self.detached = True


class Scheduler:
    def __init__(self, on_result):
        self.on_result = on_result
        self.snapshots = []
        self.closed = False
        self.sent = False

    def on_snapshot(self, snapshot):
        self.snapshots.append(snapshot)

    def tick(self):
        if self.snapshots and not self.sent:
            self.on_result("view", 8, "SYNTHETIC_ANALYSIS_BODY")
            self.sent = True

    def close(self):
        self.closed = True

    def delivery_receipt(self, identifier, generation):
        return 1

    def defer_delivery(self, *args, **kwargs):
        return True

    def mark_applied(self, *args, **kwargs):
        return True


class HostTests(unittest.TestCase):
    def host(self, script=None, **kwargs):
        script = script or Script()
        self.script = script
        self.session = Session(script)
        self.clock = Clock()
        self.states = []
        host = NativeHost({"pid": 123}, "// offline fixture", lambda _: self.session,
                          state_sink=kwargs.pop("state_sink", self.states.append),
                          scheduler_factory=Scheduler, clock=self.clock, wait=self.clock.wait,
                          seconds=kwargs.pop("seconds", .6), ready_timeout=.6,
                          restore_wait=.4, **kwargs)
        return host

    def test_latest_snapshot_routes_analysis_and_restores_before_unload(self):
        host = self.host()
        self.assertEqual(host.run(), 0)
        self.assertEqual(len(host.scheduler.snapshots), 1)
        self.assertEqual(host.scheduler.snapshots[0]["conversation"], "SECRET_PEER")
        self.assertTrue(any(call[:4] == ("annotate", "view", 8, "SYNTHETIC_ANALYSIS_BODY")
                            for call in self.script.calls))
        self.assertEqual(host.counts["resultsApplied"], 1)
        self.assertEqual(self.script.calls[-2:], [("stop",), ("unload",)])
        self.assertTrue(self.session.detached)
        self.assertTrue(host.scheduler.closed)
        self.assertEqual(self.states[-1]["phase"], "stopped")
        self.assertEqual(self.states[-1]["counts"]["restoreConfirmed"], 1)
        self.assertEqual(self.states[-1]["counts"]["fullChainValidated"], 0)

    def test_state_is_fixed_counts_and_contains_no_payloads(self):
        host = self.host()
        host.run()
        serialized = json.dumps(self.states)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("SYNTHETIC_ANALYSIS_BODY", serialized)
        self.assertTrue(all(set(state) == {"phase", "counts", "error_types"} for state in self.states))
        self.assertTrue(all(type(count) is int for state in self.states for count in state["counts"].values()))
        self.assertEqual(safe_stats({"errors": -1, "bindings": float("nan"), "applied": True}), {})

    def test_state_reads_only_coordinator_request_counters(self):
        class CountingScheduler(Scheduler):
            @property
            def request_counts(self):
                return {"requestsStarted": 2, "requestsCompleted": 1,
                        "body": "SECRET_REQUEST_BODY"}
        host = self.host()
        host.scheduler_factory = CountingScheduler
        self.assertEqual(host.run(), 0)
        self.assertEqual(self.states[-1]["counts"]["requestsStarted"], 2)
        self.assertEqual(self.states[-1]["counts"]["requestsCompleted"], 1)
        self.assertNotIn("body", self.states[-1]["counts"])

    def live_scheduler_factory(self, host):
        def factory(on_result):
            return NativeAnalysis(on_result, clock=self.clock, submit=lambda work: work(),
                analyze_fn=lambda *args, **kwargs: {"available": True, "options": [],
                                                  "risk_score": 1, "action": "Synthetic action"})
        host.scheduler_factory = factory

    def test_negative_gui_ack_retries_cached_result_then_confirms_display(self):
        script = Script(ack=False)
        host = self.host(script, seconds=4)
        self.live_scheduler_factory(host)
        def wait(seconds):
            self.clock.wait(seconds)
            if self.clock() >= .8:
                script.ack = True
        host.wait = wait
        self.assertEqual(host.run(), 0)
        calls = [call for call in script.calls if call[0] == "annotate"]
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0][4], calls[1][4])
        self.assertEqual(host.counts["requestsStarted"], 1)
        self.assertEqual(host.counts["resultsApplied"], 1)
        self.assertEqual(host.counts["resultsRejected"], 1)

    def test_only_one_native_delivery_waits_for_ack_across_three_cached_targets(self):
        class ThreeMessages(Script):
            def load(self):
                super().load()
                self.emit({"event": "snapshot", "snapshot": {"conversation": "peer-A", "messages": [
                    {"id": str(i), "generation": 1, "logicalId": str(i), "who": "her",
                     "text": f"Synthetic message {i}"} for i in range(3)]}})
        script = ThreeMessages(ack=None)
        host = self.host(script, seconds=3)
        self.live_scheduler_factory(host)
        max_pending = 0
        def wait(seconds):
            nonlocal max_pending
            self.clock.wait(seconds)
            max_pending = max(max_pending, len(host._deliveries))
        host.wait = wait
        self.assertEqual(host.run(), 0)
        calls = [call for call in script.calls if call[0] == "annotate"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(max_pending, 1)
        self.assertEqual(host.counts["requestsStarted"], 3)
        self.assertEqual(host.counts["resultsApplied"], 0)

    def test_missing_ack_expires_and_late_old_token_cannot_confirm_retry(self):
        script = Script(ack=None)
        host = self.host(script, seconds=7.5)
        self.live_scheduler_factory(host)
        late_sent = False
        def wait(seconds):
            nonlocal late_sent
            self.clock.wait(seconds)
            calls = [call for call in script.calls if call[0] == "annotate"]
            if len(calls) == 2 and not late_sent:
                script.emit({"event": "annotation_result", "deliveryId": calls[0][4], "applied": True})
                late_sent = True
        host.wait = wait
        self.assertEqual(host.run(), 0)
        self.assertTrue(late_sent)
        self.assertEqual(host.counts["deliveryTimeouts"], 1)
        self.assertEqual(host.counts["staleAcks"], 1)
        self.assertEqual(host.counts["resultsApplied"], 0)
        self.assertEqual(host.counts["requestsStarted"], 1)
        self.assertFalse(host._deliveries)

    def test_same_view_new_generation_rejects_old_ack(self):
        script = Script(ack=None)
        host = self.host(script, seconds=1.5)
        self.live_scheduler_factory(host)
        sent = False
        def wait(seconds):
            nonlocal sent
            self.clock.wait(seconds)
            calls = [call for call in script.calls if call[0] == "annotate"]
            if calls and not sent:
                sent = True
                # Invalidate and rebind on the host thread before the old GUI ack arrives.
                host.scheduler.on_snapshot({"conversation": "SECRET_PEER", "messages": [
                    {"id": "view", "generation": 9, "who": "her", "text": "SECRET_SYNTHETIC_TEXT"}]})
                script.emit({"event": "annotation_result", "deliveryId": calls[0][4], "applied": True})
        host.wait = wait
        self.assertEqual(host.run(), 0)
        self.assertEqual(host.counts["resultsApplied"], 0)
        self.assertEqual(host.counts["staleAcks"], 1)
        self.assertEqual(host.counts["requestsStarted"], 1)

    def test_missing_stop_confirmation_retries_three_times_then_detaches_failed(self):
        host = self.host(Script(stop_after=None))
        self.assertEqual(host.run(), 1)
        self.assertEqual(sum(call[0] == "stop" for call in self.script.calls), 3)
        self.assertEqual(self.states[-1]["phase"], "restore_failed")
        self.assertEqual(host.counts["restoreConfirmed"], 0)
        self.assertTrue(self.script.unloaded and self.session.detached)
        self.assertIn("RestoreConfirmationError", host.error_types)
        self.assertLess(self.clock(), 3)

    def test_second_stop_attempt_can_confirm_restore(self):
        host = self.host(Script(stop_after=2))
        self.assertEqual(host.run(), 0)
        self.assertEqual(sum(call[0] == "stop" for call in self.script.calls), 2)
        self.assertEqual(host.counts["restoreConfirmed"], 1)

    def test_heartbeats_continue_every_two_seconds(self):
        host = self.host(seconds=4.5)
        self.assertEqual(host.run(), 0)
        self.assertEqual(sum(call[0] == "heartbeat" for call in self.script.calls), 3)

    def test_observe_only_never_creates_scheduler_or_calls_annotation(self):
        host = self.host(observe_only=True)
        host.scheduler_factory = lambda _: self.fail("Observation must not create an API scheduler")
        self.assertEqual(host.run(), 0)
        self.assertIsNone(host.scheduler)
        self.assertEqual(host.counts["snapshots"], 1)
        self.assertEqual(host.counts["snapshotMessages"], 1)
        self.assertTrue(any(state["phase"] == "observing" for state in self.states))
        self.assertFalse(any(call[0] == "annotate" for call in self.script.calls))
        self.assertEqual(host.counts["heartbeats"], 1)
        self.assertNotIn("SECRET", json.dumps(self.states))

    def test_existing_stop_request_never_attaches(self):
        host = self.host(stop_requested=lambda: True)
        host.attach = lambda _: self.fail("Must not attach")
        self.assertEqual(host.run(), 0)
        self.assertEqual(self.states[-1]["phase"], "stopped_before_attach")

    def test_user_stop_during_resident_run_restores_and_returns_zero(self):
        host = self.host(seconds=None, stop_requested=lambda: self.clock() >= 1)
        self.assertEqual(host.run(), 0)
        self.assertEqual(host.counts["restoreConfirmed"], 1)
        self.assertLess(self.clock(), 2)

    def test_script_error_is_redacted_and_still_restores(self):
        host = self.host(Script(initialization_error=True))
        self.assertEqual(host.run(), 1)
        self.assertTrue(self.script.unloaded and self.session.detached)
        self.assertIn("NativeScriptError", host.error_types)
        self.assertNotIn("SECRET", json.dumps(self.states))

    def test_disk_write_error_does_not_prevent_cleanup(self):
        def failed_sink(_):
            raise OSError("SECRET_FILESYSTEM_MESSAGE")
        host = self.host(state_sink=failed_sink)
        self.assertEqual(host.run(), 1)
        self.assertTrue(self.script.unloaded and self.session.detached)
        self.assertEqual(host.counts["restoreConfirmed"], 1)
        self.assertIn("StateWriteError", host.error_types)

    def test_window_selection_prefers_main_and_rejects_ambiguous_processes(self):
        rows = [{"pid": 1, "hwnd": 11, "class": "mmui::MainWindow", "area": 100},
                {"pid": 1, "hwnd": 12, "class": "OtherWindow", "area": 200}]
        self.assertEqual(select_window(rows), (1, 11))
        rows.append({"pid": 2, "hwnd": 21, "class": "mmui::MainWindow", "area": 100})
        with self.assertRaises(TargetSelectionError):
            select_window(rows)
        self.assertEqual(select_window(rows, pid=2), (2, 21))


if __name__ == "__main__":
    unittest.main()
