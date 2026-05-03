#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayStatus<'a> {
    Booting(&'a str),
    Locked,
    Ready,
    Busy(&'a str),
    Error(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserConfirmation<'a> {
    Message { title: &'a str, body: &'a str },
    Address { network: &'a str, address: &'a str },
    Transaction { network: &'a str, summary: &'a str },
    Export { label: &'a str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserConfirmationDecision {
    Approved,
    Rejected,
    TimedOut,
}
