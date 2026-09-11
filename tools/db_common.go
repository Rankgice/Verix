package tools

import "verix/db"

// defaultDBManager 在所有 DB 系列 Tool 间共享命名连接缓存和运行时连接状态。
var defaultDBManager = db.NewManager()
