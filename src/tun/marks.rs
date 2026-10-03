//! Mark scheme aligned with sing-tun / mihomo.
//!
//! - Output mark: proxy/direct dialer sockets (SO_MARK) — packets leave via main table.
//! - Input mark:  traffic owned by auto-redirect path — may use TUN table when needed.
//!
//! Defaults match sing-tun:
//!   DefaultAutoRedirectInputMark  = 0x2023
//!   DefaultAutoRedirectOutputMark = 0x2024

pub const DEFAULT_INPUT_MARK: u32 = 0x2023;
pub const DEFAULT_OUTPUT_MARK: u32 = 0x2024;
/// Used when only auto-route (no auto-redirect) and user left mark=0.
pub const DEFAULT_ROUTE_MARK: u32 = 255;
pub const DEFAULT_TABLE: i32 = 2022;
pub const DEFAULT_RULE_PRIORITY: i32 = 9000;
pub const DEFAULT_FALLBACK_RULE_PRIORITY: i32 = 32768;

#[derive(Clone, Copy, Debug)]
pub struct TunMarks {
    pub input: u32,
    pub output: u32,
    /// True when auto-redirect is on — use dual-mark rule topology.
    pub redirect_mode: bool,
}

impl TunMarks {
    /// Resolve marks from user config + feature flags.
    pub fn resolve(user_mark: u32, auto_route: bool, auto_redirect: bool, auto_detect: bool) -> Self {
        let need = auto_route || auto_redirect || auto_detect;
        if auto_redirect {
            // Dual-mark mode (sing-tun AutoRedirectMarkMode).
            let output = if user_mark != 0 {
                user_mark
            } else {
                DEFAULT_OUTPUT_MARK
            };
            let input = if user_mark != 0 && user_mark != DEFAULT_OUTPUT_MARK {
                // keep input distinct from output
                if user_mark == DEFAULT_INPUT_MARK {
                    DEFAULT_OUTPUT_MARK
                } else {
                    DEFAULT_INPUT_MARK
                }
            } else {
                DEFAULT_INPUT_MARK
            };
            // Ensure input != output
            let input = if input == output {
                DEFAULT_INPUT_MARK.wrapping_add(1)
            } else {
                input
            };
            Self {
                input,
                output,
                redirect_mode: true,
            }
        } else if need {
            let output = if user_mark != 0 {
                user_mark
            } else {
                DEFAULT_ROUTE_MARK
            };
            Self {
                input: output, // unused in single-mark mode
                output,
                redirect_mode: false,
            }
        } else {
            Self {
                input: 0,
                output: user_mark,
                redirect_mode: false,
            }
        }
    }
}
