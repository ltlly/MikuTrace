"""脱敏 host 扩展：用户文件加载，不修改 traceMiku 源码。"""
API_VERSION = 1


def prepare(ctx):
    return {"prepared": True}


def on_ready(ctx):
    # 可通过 agent 插件 invoke 构造目标专用的触发器。
    return ctx["script"].exports_sync.plugin_call("demo", {
        "message": ctx["config"]["message"],
    })


def finish(ctx):
    return {"finished": True}
