use crate::scoped::{AdmissionScope, ResourceClass, ScopedBuffer, ScopedFault};

pub(super) struct Packet<R> {
    bytes: ScopedBuffer<R>,
    site: &'static str,
}

pub(super) fn length(site: &'static str, parts: &[usize]) -> Result<usize, ScopedFault> {
    parts.iter().try_fold(0usize, |sum, part| {
        sum.checked_add(*part)
            .ok_or_else(|| ScopedFault::overflow(site))
    })
}

impl<R: Send + Sync + 'static> Packet<R> {
    pub(super) fn new<S: AdmissionScope<Reservation = R>>(
        scope: &S,
        site: &'static str,
        capacity: usize,
    ) -> Result<Self, ScopedFault> {
        u32::try_from(capacity).map_err(|_| ScopedFault::overflow(site))?;
        Ok(Self {
            bytes: ScopedBuffer::try_with_capacity(scope, ResourceClass::Secret, site, capacity)?,
            site,
        })
    }

    pub(super) fn byte<S: AdmissionScope<Reservation = R>>(
        &mut self,
        scope: &S,
        value: u8,
    ) -> Result<(), ScopedFault> {
        self.bytes.try_extend_from_slice(scope, &[value])
    }

    pub(super) fn word<S: AdmissionScope<Reservation = R>>(
        &mut self,
        scope: &S,
        value: u32,
    ) -> Result<(), ScopedFault> {
        self.bytes
            .try_extend_from_slice(scope, &value.to_be_bytes())
    }

    pub(super) fn string<S: AdmissionScope<Reservation = R>>(
        &mut self,
        scope: &S,
        value: &[u8],
    ) -> Result<(), ScopedFault> {
        let len = u32::try_from(value.len()).map_err(|_| ScopedFault::overflow(self.site))?;
        self.word(scope, len)?;
        self.bytes.try_extend_from_slice(scope, value)
    }

    pub(super) fn finish(self) -> ScopedBuffer<R> {
        self.bytes
    }
}
