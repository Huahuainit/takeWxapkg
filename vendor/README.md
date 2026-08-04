# Vendor Runtime

`wx_decompiler_runtime/` 是本地可选反编译运行时目录。

该目录已被 `.gitignore` 排除，不建议直接提交到公开仓库。

本机打包 exe 时，如果该目录存在，`takeWxapkg.spec` 会自动把它嵌入 onefile exe。
如果该目录不存在，程序仍可运行，但会退回到内置 Python 解包和兼容生成流程。
