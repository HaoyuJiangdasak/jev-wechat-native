"""测试对方消息12条限制的优化效果"""

import _bootstrap  # noqa: F401  (puts app/ on sys.path)
import sys
from pathlib import Path

# 设置输出编码为UTF-8
sys.stdout.reconfigure(encoding='utf-8')

# 添加模块路径
sys.path.insert(0, str(Path(__file__).parent))

from native_analysis import NativeAnalysis, format_analysis

def test_her_message_limit():
    """测试只保留对方最近12条消息"""
    results = []

    def mock_result(msg_id, generation, text):
        results.append((msg_id, generation, text))
        return True

    # 模拟分析函数：返回消息数统计
    def mock_analyze(messages, **kwargs):
        try:
            her_count = sum(1 for m in messages if m[0] == "her")
            me_count = sum(1 for m in messages if m[0] == "me")
            total = len(messages)
            print(f"[mock_analyze] 收到 {total} 条消息，其中对方 {her_count} 条")
            return {
                "available": True,
                "question_title": f"共{total}条消息",
                "options": [
                    {"label": f"对方{her_count}条", "probability": 0.6},
                    {"label": f"我{me_count}条", "probability": 0.4}
                ],
                "risk_score": 1.0,
                "action": f"上下文：对方{her_count}条+我{me_count}条"
            }
        except Exception as e:
            print(f"[mock_analyze] 错误: {e}")
            import traceback
            traceback.print_exc()
            raise

    work_queue = []
    def mock_submit(work):
        work_queue.append(work)

    scheduler = NativeAnalysis(
        mock_result,
        analyze_fn=mock_analyze,
        submit=mock_submit,
        context=12
    )

    # 构造20条对方消息 + 20条我的回复的场景
    messages = []
    for i in range(20):
        messages.append({
            "id": f"her_{i}",
            "generation": 1,
            "who": "her",
            "text": f"对方消息 {i+1}",
            "targetEligible": i >= 17  # 只有最后3条是候选
        })
        messages.append({
            "id": f"me_{i}",
            "generation": 1,
            "who": "me",
            "text": f"我的回复 {i+1}",
            "targetEligible": False
        })

    print("测试场景：20条对方消息 + 20条我的回复（共40条）")
    print("预期：只保留对方最近12条消息及相关上下文\n")

    scheduler.on_snapshot({
        "conversation": "test_peer",
        "messages": messages
    })

    # 执行排队的分析任务
    if work_queue:
        work_queue[0]()
        scheduler.tick()

    if results:
        print(f"[OK] 分析结果：{results[0][2]}")
        print(f"[OK] 消息ID：{results[0][0]}")
    else:
        print("[FAIL] 未生成分析结果")

    # 测试候选数量
    print(f"\n候选消息数：{len(scheduler.candidates)}")
    print(f"预期候选数：3（最后3条对方消息）")

    return len(results) > 0

def test_context_fingerprint():
    """测试上下文指纹变化和裁剪"""
    results = []

    def mock_result(msg_id, generation, text):
        results.append((msg_id, generation, text))
        return True

    def mock_analyze(messages, **kwargs):
        her_count = sum(1 for m in messages if m[0] == "her")
        total = len(messages)
        return {
            "available": True,
            "question_title": "测试",
            "options": [{"label": f"her:{her_count}/total:{total}", "probability": 1.0}],
            "risk_score": 0,
            "action": "测试"
        }

    work_queue = []
    def mock_submit(work):
        work_queue.append(work)

    scheduler = NativeAnalysis(
        mock_result,
        analyze_fn=mock_analyze,
        submit=mock_submit,
        context=12
    )

    # 第一次：10条对方消息
    messages_10 = []
    for i in range(10):
        messages_10.append({
            "id": f"msg_{i}",
            "generation": 1,
            "who": "her",
            "text": f"消息 {i}",
            "logicalId": f"logical_{i}",
            "targetEligible": i == 9
        })

    scheduler.on_snapshot({"conversation": "test", "messages": messages_10})
    if work_queue:
        work_queue.pop(0)()
        scheduler.tick()

    # 第二次：15条对方消息（应该被裁剪到最近12条）
    messages_15 = []
    for i in range(15):
        messages_15.append({
            "id": f"msg2_{i}",  # 不同的消息ID
            "generation": 1,
            "who": "her",
            "text": f"新消息 {i}",  # 不同的文本内容
            "logicalId": f"logical2_{i}",
            "targetEligible": i == 14
        })

    scheduler.on_snapshot({"conversation": "test", "messages": messages_15})
    print(f"第二次快照后候选数：{len(scheduler.candidates)}")
    if scheduler.candidates:
        print(f"候选消息ID：{[c.id for c in scheduler.candidates]}")
        print(f"候选上下文长度：{[len(c.turns) for c in scheduler.candidates]}")
    print(f"工作队列长度：{len(work_queue)}")
    if work_queue:
        print("执行工作队列中的任务...")
        print(f"执行前结果数：{len(results)}")
        # 执行工作函数（它会自己调用 analyze 并裁剪上下文）
        work_fn = work_queue.pop(0)
        print(f"执行工作函数：{work_fn}")
        work_fn()
        print(f"执行后、tick前结果数：{len(results)}")

        # 推进时钟以绕过速率限制
        import time
        time.sleep(3.5)  # 等待超过 DELIVERY_INTERVAL_SECONDS (3秒)

        # 调用 tick 处理完成的结果
        scheduler.tick()
        print(f"tick后结果数：{len(results)}")
    else:
        print("工作队列为空")

    print("\n上下文裁剪测试：")
    print(f"结果数量：{len(results)}")
    if results:
        print(f"结果元组长度：{len(results[0])}")
        print(f"第一个结果：{results[0]}")
    if len(results) >= 2:
        print(f"第二个结果：{results[1]}")
        print(f"15条消息场景：{results[1][2]}")
        # 验证15条场景只保留了12条对方消息
        if "her:12/total:12" in results[1][2]:
            print("✓ 预期：15条场景被裁剪到12条 [通过]")
            return True
        else:
            print(f"✗ 预期：15条场景应该被裁剪到12条 [失败]")
            print(f"实际结果：{results[1][2]}")
            return False
    else:
        print("✗ 预期：15条场景应该被裁剪到12条 [失败 - 缺少第二个结果]")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Native Analysis 上下文优化测试")
    print("=" * 60 + "\n")

    test1 = test_her_message_limit()
    print("\n" + "-" * 60 + "\n")
    test2 = test_context_fingerprint()

    print("\n" + "=" * 60)
    print(f"测试结果：{'全部通过 [OK]' if test1 and test2 else '存在失败 [FAIL]'}")
    print("=" * 60)
