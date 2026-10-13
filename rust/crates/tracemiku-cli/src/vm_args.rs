use anyhow::Context;
use std::num::NonZeroU64;
use tracemiku_core::analysis::reports::VmProfile;

#[derive(Debug, clap::Args)]
pub(super) struct VmArgs {
    /// VM 指令指针寄存器；启用 VM 分析时必填（x0–x30、sp/fp/lr）。
    #[arg(long)]
    vm_ip_reg: Option<String>,
    /// VM 状态区基址寄存器；启用 VM 分析时必填。
    #[arg(long)]
    vm_state_reg: Option<String>,
    /// VM 派发表基址寄存器；启用 VM 分析时必填。
    #[arg(long)]
    vm_dispatch_reg: Option<String>,
    /// VM 状态槽间距（正整数字节数）；启用 VM 分析时必填，无隐式布局。
    #[arg(long)]
    vm_slot_bytes: Option<NonZeroU64>,
    /// 回溯时降低优先级的额外寄存器，逗号分隔；始终包括三个角色及 sp/fp/lr。
    #[arg(long)]
    vm_infra_regs: Option<String>,
}

impl VmArgs {
    pub(super) fn into_profile(self) -> anyhow::Result<VmProfile> {
        VmProfile::new(
            self.vm_ip_reg
                .context("--vm-ip-reg is required for VM analysis")?,
            self.vm_state_reg
                .context("--vm-state-reg is required for VM analysis")?,
            self.vm_dispatch_reg
                .context("--vm-dispatch-reg is required for VM analysis")?,
            self.vm_slot_bytes
                .context("--vm-slot-bytes is required for VM analysis")?,
            self.vm_infra_regs.unwrap_or_default(),
        )
    }
}
