use crate::{CoreError, CoreResult};

pub const OTA_HASH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaKind {
    Full,
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaHashType {
    FullFirmware,
    CompressedUpload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtaRequest {
    pub kind: OtaKind,
    pub firmware_size: u64,
    pub compressed_size: u64,
    pub patch_size: Option<u64>,
    pub hash_type: OtaHashType,
    pub expected_hash: [u8; OTA_HASH_LEN],
    pub extended_replies: bool,
}

pub trait OtaImageWriter {
    type Error;

    fn begin(&mut self, request: &OtaRequest) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Self::Error>;
    fn finish(&mut self, request: &OtaRequest, received_compressed: u64)
        -> Result<(), Self::Error>;
    fn abort(&mut self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtaWriteError<E> {
    Writer(E),
    TooMuchData,
    IncompleteUpload,
    Finalized,
}

#[derive(Debug)]
pub struct OtaWriteSession<W: OtaImageWriter> {
    request: OtaRequest,
    received_compressed: u64,
    writer: Option<W>,
    finalized: bool,
}

impl<W> OtaWriteSession<W>
where
    W: OtaImageWriter,
{
    pub fn begin(mut writer: W, request: OtaRequest) -> Result<Self, OtaWriteError<W::Error>> {
        writer.begin(&request).map_err(OtaWriteError::Writer)?;
        Ok(Self {
            request,
            received_compressed: 0,
            writer: Some(writer),
            finalized: false,
        })
    }

    pub fn request(&self) -> &OtaRequest {
        &self.request
    }

    pub fn received_compressed(&self) -> u64 {
        self.received_compressed
    }

    pub fn progress_percent(&self) -> u64 {
        self.request
            .upload_progress_percent(self.received_compressed)
    }

    pub fn writer(&self) -> Option<&W> {
        self.writer.as_ref()
    }

    pub fn writer_mut(&mut self) -> Option<&mut W> {
        self.writer.as_mut()
    }

    pub fn write(&mut self, data: &[u8]) -> Result<u64, OtaWriteError<W::Error>> {
        if self.finalized {
            return Err(OtaWriteError::Finalized);
        }

        let next = self
            .received_compressed
            .checked_add(data.len() as u64)
            .ok_or(OtaWriteError::TooMuchData)?;
        if next > self.request.compressed_size {
            return Err(OtaWriteError::TooMuchData);
        }

        let writer = self.writer.as_mut().ok_or(OtaWriteError::Finalized)?;
        writer
            .write(self.received_compressed, data)
            .map_err(OtaWriteError::Writer)?;
        self.received_compressed = next;
        Ok(self.progress_percent())
    }

    pub fn finish(mut self) -> Result<W, OtaWriteError<W::Error>> {
        if self.finalized {
            return Err(OtaWriteError::Finalized);
        }
        if self.received_compressed != self.request.compressed_size {
            return Err(OtaWriteError::IncompleteUpload);
        }

        let mut writer = self.writer.take().ok_or(OtaWriteError::Finalized)?;
        if let Err(err) = writer.finish(&self.request, self.received_compressed) {
            writer.abort();
            self.finalized = true;
            return Err(OtaWriteError::Writer(err));
        }
        self.finalized = true;
        Ok(writer)
    }

    pub fn abort(mut self) -> Option<W> {
        self.writer.take().map(|mut writer| {
            if !self.finalized {
                writer.abort();
                self.finalized = true;
            }
            writer
        })
    }
}

impl<W> Drop for OtaWriteSession<W>
where
    W: OtaImageWriter,
{
    fn drop(&mut self) {
        if !self.finalized {
            if let Some(writer) = self.writer.as_mut() {
                writer.abort();
            }
            self.finalized = true;
        }
    }
}

impl OtaRequest {
    pub fn full(
        firmware_size: u64,
        compressed_size: u64,
        full_firmware_hash: Option<[u8; OTA_HASH_LEN]>,
        compressed_upload_hash: Option<[u8; OTA_HASH_LEN]>,
        extended_replies: bool,
    ) -> CoreResult<Self> {
        validate_full_sizes(firmware_size, compressed_size)?;
        let (hash_type, expected_hash) = select_hash(full_firmware_hash, compressed_upload_hash)?;

        Ok(Self {
            kind: OtaKind::Full,
            firmware_size,
            compressed_size,
            patch_size: None,
            hash_type,
            expected_hash,
            extended_replies,
        })
    }

    pub fn delta(
        firmware_size: u64,
        patch_size: u64,
        compressed_size: u64,
        full_firmware_hash: Option<[u8; OTA_HASH_LEN]>,
        compressed_upload_hash: Option<[u8; OTA_HASH_LEN]>,
        extended_replies: bool,
    ) -> CoreResult<Self> {
        validate_full_sizes(firmware_size, compressed_size)?;
        if patch_size <= compressed_size {
            return Err(CoreError::BadParameters);
        }
        let (hash_type, expected_hash) = select_hash(full_firmware_hash, compressed_upload_hash)?;

        Ok(Self {
            kind: OtaKind::Delta,
            firmware_size,
            compressed_size,
            patch_size: Some(patch_size),
            hash_type,
            expected_hash,
            extended_replies,
        })
    }

    pub fn upload_progress_percent(&self, received_compressed: u64) -> u64 {
        if self.compressed_size == 0 {
            return 0;
        }

        received_compressed
            .saturating_mul(100)
            .checked_div(self.compressed_size)
            .unwrap_or(0)
            .min(100)
    }
}

fn validate_full_sizes(firmware_size: u64, compressed_size: u64) -> CoreResult<()> {
    if firmware_size <= compressed_size {
        return Err(CoreError::BadParameters);
    }
    Ok(())
}

fn select_hash(
    full_firmware_hash: Option<[u8; OTA_HASH_LEN]>,
    compressed_upload_hash: Option<[u8; OTA_HASH_LEN]>,
) -> CoreResult<(OtaHashType, [u8; OTA_HASH_LEN])> {
    if let Some(hash) = full_firmware_hash {
        Ok((OtaHashType::FullFirmware, hash))
    } else if let Some(hash) = compressed_upload_hash {
        Ok((OtaHashType::CompressedUpload, hash))
    } else {
        Err(CoreError::BadParameters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;

    #[test]
    fn full_ota_validates_sizes_and_prefers_final_firmware_hash() {
        let full_hash = [0x11; OTA_HASH_LEN];
        let compressed_hash = [0x22; OTA_HASH_LEN];

        let request =
            OtaRequest::full(1_000, 600, Some(full_hash), Some(compressed_hash), true).unwrap();

        assert_eq!(request.kind, OtaKind::Full);
        assert_eq!(request.hash_type, OtaHashType::FullFirmware);
        assert_eq!(request.expected_hash, full_hash);
        assert!(request.extended_replies);
        assert_eq!(request.upload_progress_percent(300), 50);
    }

    #[test]
    fn full_ota_accepts_legacy_compressed_hash() {
        let compressed_hash = [0x22; OTA_HASH_LEN];

        let request = OtaRequest::full(1_000, 600, None, Some(compressed_hash), false).unwrap();

        assert_eq!(request.hash_type, OtaHashType::CompressedUpload);
        assert_eq!(request.expected_hash, compressed_hash);
    }

    #[test]
    fn delta_ota_requires_patch_larger_than_compressed_upload() {
        assert_eq!(
            OtaRequest::delta(1_000, 600, 600, None, Some([0x22; OTA_HASH_LEN]), false),
            Err(CoreError::BadParameters)
        );

        let request =
            OtaRequest::delta(1_000, 700, 600, None, Some([0x22; OTA_HASH_LEN]), false).unwrap();
        assert_eq!(request.kind, OtaKind::Delta);
        assert_eq!(request.patch_size, Some(700));
    }

    #[test]
    fn ota_requires_hash_and_firmware_larger_than_compressed_upload() {
        assert_eq!(
            OtaRequest::full(600, 600, None, Some([0x22; OTA_HASH_LEN]), false),
            Err(CoreError::BadParameters)
        );
        assert_eq!(
            OtaRequest::full(1_000, 600, None, None, false),
            Err(CoreError::BadParameters)
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TestWriteError {
        Fail,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestWriter {
        writes: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)>,
        begun: bool,
        finished: bool,
        aborted: bool,
        fail_write: bool,
    }

    impl TestWriter {
        fn new() -> Self {
            Self {
                writes: alloc::vec::Vec::new(),
                begun: false,
                finished: false,
                aborted: false,
                fail_write: false,
            }
        }
    }

    impl OtaImageWriter for TestWriter {
        type Error = TestWriteError;

        fn begin(&mut self, _request: &OtaRequest) -> Result<(), Self::Error> {
            self.begun = true;
            Ok(())
        }

        fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
            if self.fail_write {
                return Err(TestWriteError::Fail);
            }
            self.writes.push((offset, data.to_vec()));
            Ok(())
        }

        fn finish(
            &mut self,
            _request: &OtaRequest,
            _received_compressed: u64,
        ) -> Result<(), Self::Error> {
            self.finished = true;
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted = true;
        }
    }

    #[derive(Debug, Clone)]
    struct SharedAbortWriter {
        aborted: Rc<Cell<bool>>,
    }

    impl OtaImageWriter for SharedAbortWriter {
        type Error = ();

        fn begin(&mut self, _request: &OtaRequest) -> Result<(), Self::Error> {
            Ok(())
        }

        fn write(&mut self, _offset: u64, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn finish(
            &mut self,
            _request: &OtaRequest,
            _received_compressed: u64,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted.set(true);
        }
    }

    #[test]
    fn ota_write_session_streams_chunks_with_offsets_and_progress() {
        let request =
            OtaRequest::full(1_000, 600, None, Some([0x22; OTA_HASH_LEN]), false).unwrap();
        let mut session = OtaWriteSession::begin(TestWriter::new(), request).unwrap();

        assert!(session.writer().unwrap().begun);
        assert_eq!(session.write(&[1; 150]).unwrap(), 25);
        assert_eq!(session.write(&[2; 450]).unwrap(), 100);
        assert_eq!(
            session.writer().unwrap().writes,
            alloc::vec![(0, alloc::vec![1; 150]), (150, alloc::vec![2; 450])]
        );

        let writer = session.finish().unwrap();
        assert!(writer.finished);
        assert!(!writer.aborted);
    }

    #[test]
    fn ota_write_session_rejects_overflow_and_incomplete_finish() {
        let request =
            OtaRequest::full(1_000, 600, None, Some([0x22; OTA_HASH_LEN]), false).unwrap();
        let mut session = OtaWriteSession::begin(TestWriter::new(), request).unwrap();

        assert_eq!(session.write(&[0; 601]), Err(OtaWriteError::TooMuchData));
        assert_eq!(session.write(&[0; 300]).unwrap(), 50);
        assert_eq!(session.finish(), Err(OtaWriteError::IncompleteUpload));
    }

    #[test]
    fn ota_write_session_aborts_unfinished_writer() {
        let request =
            OtaRequest::full(1_000, 600, None, Some([0x22; OTA_HASH_LEN]), false).unwrap();
        let mut session = OtaWriteSession::begin(TestWriter::new(), request).unwrap();
        session.write(&[0; 300]).unwrap();

        let writer = session.abort().unwrap();
        assert!(writer.aborted);
        assert!(!writer.finished);
    }

    #[test]
    fn ota_write_session_aborts_when_dropped_or_failed_finish() {
        let request =
            OtaRequest::full(1_000, 600, None, Some([0x22; OTA_HASH_LEN]), false).unwrap();

        let dropped_abort = Rc::new(Cell::new(false));
        {
            let mut session = OtaWriteSession::begin(
                SharedAbortWriter {
                    aborted: dropped_abort.clone(),
                },
                request,
            )
            .unwrap();
            session.write(&[0; 300]).unwrap();
        }
        assert!(dropped_abort.get());

        let failed_finish_abort = Rc::new(Cell::new(false));
        let mut session = OtaWriteSession::begin(
            SharedAbortWriter {
                aborted: failed_finish_abort.clone(),
            },
            request,
        )
        .unwrap();
        session.write(&[0; 300]).unwrap();
        assert!(matches!(
            session.finish(),
            Err(OtaWriteError::IncompleteUpload)
        ));
        assert!(failed_finish_abort.get());
    }
}
