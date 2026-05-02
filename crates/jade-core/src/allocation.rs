#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationBudget {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_scratch_bytes: usize,
}

impl AllocationBudget {
    pub const ESP32_NO_SPIRAM: Self = Self {
        max_request_bytes: 17 * 1024,
        max_response_bytes: 3 * 1024,
        max_scratch_bytes: 8 * 1024,
    };

    pub const ESP32_SPIRAM: Self = Self {
        max_request_bytes: 401 * 1024,
        max_response_bytes: 3 * 1024,
        max_scratch_bytes: 64 * 1024,
    };

    pub fn ensure_request(self, len: usize) -> Result<(), AllocationFailure> {
        if len > self.max_request_bytes {
            return Err(AllocationFailure::RequestTooLarge {
                requested: len,
                limit: self.max_request_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationFailure {
    RequestTooLarge { requested: usize, limit: usize },
    ResponseTooLarge { requested: usize, limit: usize },
    ScratchTooLarge { requested: usize, limit: usize },
    AllocatorReturnedNull,
}
