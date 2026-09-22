use libc::{c_int, c_uint};

pub type PamFlag = c_uint;
pub type PamItemType = c_int;
pub type PamMessageStyle = c_int;

pub const PAM_SILENT: PamFlag = 0x80000000;
pub const PAM_DISALLOW_NULL_AUTHTOK: PamFlag = 0x1;
pub const PAM_ESTABLISH_CRED: PamFlag = 0x1;
pub const PAM_DELETE_CRED: PamFlag = 0x2;
pub const PAM_REINITIALIZE_CRED: PamFlag = 0x4;
pub const PAM_REFRESH_CRED: PamFlag = 0x8;
pub const PAM_PRELIM_CHECK: PamFlag = 0x1;
pub const PAM_UPDATE_AUTHTOK: PamFlag = 0x2;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x4;

pub const PAM_PROMPT_ECHO_OFF: PamMessageStyle = 1;
pub const PAM_PROMPT_ECHO_ON: PamMessageStyle = 2;
pub const PAM_ERROR_MSG: PamMessageStyle = 3;
pub const PAM_TEXT_INFO: PamMessageStyle = 4;
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq, Eq)]
#[repr(i32)]
#[non_exhaustive]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_OPEN_ERR = 1,
    PAM_SYMBOL_ERR = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR = 5,
    PAM_CONV_ERR = 6,
    PAM_PERM_DENIED = 7,
    PAM_MAXTRIES = 8,
    PAM_AUTH_ERR = 9,
    PAM_NEW_AUTHTOK_REQD = 10,
    PAM_CRED_INSUFFICIENT = 11,
    PAM_AUTHINFO_UNAVAIL = 12,
    PAM_USER_UNKNOWN = 13,
    PAM_CRED_UNAVAIL = 14,
    PAM_CRED_EXPIRED = 15,
    PAM_CRED_ERR = 16,
    PAM_ACCT_EXPIRED = 17,
    PAM_AUTHTOK_EXPIRED = 18,
    PAM_SESSION_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_NO_MODULE_DATA = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_TRY_AGAIN = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_DOMAIN_UNKNOWN = 29,
    PAM_APPLE_ACCT_TEMP_LOCK = 1024,
    PAM_APPLE_ACCT_LOCKED = 1025,
    PAM_APPLE_KEK_ERROR = 1026,
    PAM_APPLE_WRONG_CARD = 1027,
}

impl TryFrom<c_int> for PamResultCode {
    type Error = c_int;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::PAM_SUCCESS,
            1 => Self::PAM_OPEN_ERR,
            2 => Self::PAM_SYMBOL_ERR,
            3 => Self::PAM_SERVICE_ERR,
            4 => Self::PAM_SYSTEM_ERR,
            5 => Self::PAM_BUF_ERR,
            6 => Self::PAM_CONV_ERR,
            7 => Self::PAM_PERM_DENIED,
            8 => Self::PAM_MAXTRIES,
            9 => Self::PAM_AUTH_ERR,
            10 => Self::PAM_NEW_AUTHTOK_REQD,
            11 => Self::PAM_CRED_INSUFFICIENT,
            12 => Self::PAM_AUTHINFO_UNAVAIL,
            13 => Self::PAM_USER_UNKNOWN,
            14 => Self::PAM_CRED_UNAVAIL,
            15 => Self::PAM_CRED_EXPIRED,
            16 => Self::PAM_CRED_ERR,
            17 => Self::PAM_ACCT_EXPIRED,
            18 => Self::PAM_AUTHTOK_EXPIRED,
            19 => Self::PAM_SESSION_ERR,
            20 => Self::PAM_AUTHTOK_ERR,
            21 => Self::PAM_AUTHTOK_RECOVERY_ERR,
            22 => Self::PAM_AUTHTOK_LOCK_BUSY,
            23 => Self::PAM_AUTHTOK_DISABLE_AGING,
            24 => Self::PAM_NO_MODULE_DATA,
            25 => Self::PAM_IGNORE,
            26 => Self::PAM_ABORT,
            27 => Self::PAM_TRY_AGAIN,
            28 => Self::PAM_MODULE_UNKNOWN,
            29 => Self::PAM_DOMAIN_UNKNOWN,
            1024 => Self::PAM_APPLE_ACCT_TEMP_LOCK,
            1025 => Self::PAM_APPLE_ACCT_LOCKED,
            1026 => Self::PAM_APPLE_KEK_ERROR,
            1027 => Self::PAM_APPLE_WRONG_CARD,
            other => return Err(other),
        })
    }
}

impl PamResultCode {
    pub(crate) fn from_raw(value: c_int) -> Self {
        Self::try_from(value).unwrap_or(Self::PAM_SYSTEM_ERR)
    }
}
