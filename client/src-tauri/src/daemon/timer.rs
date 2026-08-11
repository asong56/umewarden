/// 自动锁定计时器
///
/// 用户无操作超过指定时长后自动发送 Lock 指令。
/// 每次 vault 操作时通过 reset() 重置。

use super::DaemonMsg;
use std::time::Duration;
use tokio::{
    sync::mpsc,
    time::{sleep, Instant},
};

/// Spawn 自动锁定 task，返回 reset sender
/// 向 reset_tx 发送任意值即可重置计时器。
pub fn spawn_auto_lock(
    daemon_tx: mpsc::Sender<DaemonMsg>,
    timeout: Duration,
) -> mpsc::Sender<()> {
    let (reset_tx, mut reset_rx) = mpsc::channel::<()>(4);

    tauri::async_runtime::spawn(async move {
        loop {
            tokio::select! {
                // 计时器到期 → 锁定
                _ = sleep(timeout) => {
                    log::info!("auto-lock triggered after {:?}", timeout);
                    let _ = daemon_tx.send(DaemonMsg::Lock).await;
                    // 锁定后进入等待，直到下次 reset（即 unlock）
                    let _ = reset_rx.recv().await;
                }
                // 收到 reset 信号 → 重新计时
                Some(_) = reset_rx.recv() => {
                    log::debug!("auto-lock timer reset");
                    // loop 重新开始，sleep 重置
                }
            }
        }
    });

    reset_tx
}
