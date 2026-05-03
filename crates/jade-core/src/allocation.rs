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

    pub fn ensure_response(self, len: usize) -> Result<(), AllocationFailure> {
        if len > self.max_response_bytes {
            return Err(AllocationFailure::ResponseTooLarge {
                requested: len,
                limit: self.max_response_bytes,
            });
        }
        Ok(())
    }

    pub fn ensure_scratch(self, len: usize) -> Result<(), AllocationFailure> {
        if len > self.max_scratch_bytes {
            return Err(AllocationFailure::ScratchTooLarge {
                requested: len,
                limit: self.max_scratch_bytes,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_budget_checks_each_region_independently() {
        let budget = AllocationBudget {
            max_request_bytes: 8,
            max_response_bytes: 4,
            max_scratch_bytes: 2,
        };

        assert_eq!(budget.ensure_request(8), Ok(()));
        assert_eq!(
            budget.ensure_request(9),
            Err(AllocationFailure::RequestTooLarge {
                requested: 9,
                limit: 8
            })
        );
        assert_eq!(budget.ensure_response(4), Ok(()));
        assert_eq!(
            budget.ensure_response(5),
            Err(AllocationFailure::ResponseTooLarge {
                requested: 5,
                limit: 4
            })
        );
        assert_eq!(budget.ensure_scratch(2), Ok(()));
        assert_eq!(
            budget.ensure_scratch(3),
            Err(AllocationFailure::ScratchTooLarge {
                requested: 3,
                limit: 2
            })
        );
    }
}
