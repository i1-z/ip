export default {
  async fetch(request, env) {
    // 1. 定义目标 KV 的密钥名称（已修改为大写 ADD.txt）
    const TARGET_KEY = "ADD.txt";
    
    // 注意：这里的 env.KV 请确保与您在 Cloudflare 后台绑定的 KV 变量名称大小写一致
    const kvStore = env.KV; 

    if (!kvStore) {
      return new Response("错误：未检测到 KV 空间绑定，请在后台设置中绑定变量名为 KV 的命名空间。", { 
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    // 2. 处理网页表单提交（POST 请求：更新 ADD.txt 内容）
    if (request.method === "POST") {
      try {
        const formData = await request.formData();
        const newContent = formData.get("content") || "";
        
        // 将新内容写入 KV 空间的 ADD.txt 中
        await kvStore.put(TARGET_KEY, newContent);
        
        return new Response(renderHTML(TARGET_KEY, newContent, `✅ 保存成功！${TARGET_KEY} 内容已更新。`), {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      } catch (err) {
        return new Response("保存失败: " + err.message, { status: 500 });
      }
    }

    // 3. 处理网页访问（GET 请求：读取当前 ADD.txt 内容并显示输入框）
    const currentContent = (await kvStore.get(TARGET_KEY)) || "";
    return new Response(renderHTML(TARGET_KEY, currentContent, ""), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};

// 辅助函数：生成简洁的网页输入界面
function renderHTML(keyName, content, message) {
  const safeContent = content
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>编辑 KV - ${keyName}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 680px; margin: 40px auto; padding: 0 20px; background: #f9fafb; }
    .card { background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h2 { margin-top: 0; color: #1f2937; font-size: 1.25rem; }
    textarea { width: 100%; height: 280px; padding: 12px; box-sizing: border-box; border: 1px solid #d1d5db; border-radius: 6px; font-family: monospace; font-size: 14px; resize: vertical; }
    button { margin-top: 16px; background: #2563eb; color: white; border: none; padding: 10px 24px; border-radius: 6px; font-size: 15px; cursor: pointer; }
    button:hover { background: #1d4ed8; }
    .msg { margin-bottom: 12px; color: #059669; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <h2>更改 KV 空间密钥：<code>${keyName}</code></h2>
    ${message ? `<div class="msg">${message}</div>` : ""}
    <form method="POST">
      <textarea name="content" placeholder="在此直接输入 ${keyName} 的内容（支持多行）...">${safeContent}</textarea>
      <button type="submit">保存更改</button>
    </form>
  </div>
</body>
</html>
  `;
}
