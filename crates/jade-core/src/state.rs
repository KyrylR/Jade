use jade_protocol_v2::SessionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletLifecycle {
    Uninit,
    Unsaved,
    Locked,
    Ready,
    Temporary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    Internal,
    Serial,
    Ble,
    QemuTcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceSession {
    pub id: SessionId,
    pub interface: InterfaceKind,
    pub authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    Idle,
    ClientMessage,
    UiNavigation,
    Signing { session: SessionId },
    Ota { session: SessionId },
}
