use std::future::Future;
use std::ops::Range;

use crate::scoped::{AdmissionScope, ResourceRoot, ScopedBuffer, ScopedFault};
use crate::{Error, msg};

use super::ClientResult;
use super::auth::{self, Cursor};
use super::packet;

/// 签名服务借用已拥有的 key/agent。私钥和外置服务资源由其原操作根持有。
/// 实现须在其内部任何分配前准入，并返回有根的 SSH signature blob；不得导出私钥。
pub trait ScopedSigner<S: AdmissionScope>: Send {
    type Error: Send + Sync + 'static;

    fn sign(
        &mut self,
        scope: &S,
        request: &ScopedSignRequest<S::Reservation>,
        hash_alg: Option<ssh_key::HashAlg>,
    ) -> impl Future<
        Output = ClientResult<ScopedBuffer<S::Reservation>, Self::Error, S::Reservation>,
    > + Send;
}

/// session-id 与 USERAUTH_REQUEST 共用同一 Secret backing，不通过裸 Vec 交付。
pub struct ScopedSignRequest<R> {
    bytes: ScopedBuffer<R>,
    request_offset: usize,
    algorithm: Range<usize>,
    key: Range<usize>,
}

impl<R: Send + Sync + 'static> ScopedSignRequest<R> {
    pub fn data(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn root(&self) -> &ResourceRoot<R> {
        self.bytes.root()
    }

    pub fn algorithm(&self) -> &str {
        let bytes = self
            .bytes
            .as_slice()
            .split_at(self.algorithm.start)
            .1
            .split_at(self.algorithm.len())
            .0;
        // 私有构造函数已验证 UTF-8 与范围；对外只提供不可变访问。
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }

    pub fn public_key_blob(&self) -> &[u8] {
        self.bytes
            .as_slice()
            .split_at(self.key.start)
            .1
            .split_at(self.key.len())
            .0
    }

    pub(super) fn from_reply(
        bytes: crate::scoped::ErasedBuffer,
        request_offset: usize,
    ) -> Result<Self, ScopedFault> {
        let bytes = bytes.into_typed::<R>()?;
        let Some(payload) = bytes.as_slice().get(request_offset..) else {
            return Err(ScopedFault::overflow("client.auth.sign.offset"));
        };
        let (_, algorithm, key) =
            ranges(payload).map_err(|_| ScopedFault::overflow("client.auth.sign.fields"))?;
        Ok(Self {
            bytes,
            request_offset,
            algorithm: algorithm.start + request_offset..algorithm.end + request_offset,
            key: key.start + request_offset..key.end + request_offset,
        })
    }

    pub(super) fn signed<S: AdmissionScope<Reservation = R>>(
        self,
        scope: &S,
        id: u64,
        signature: ScopedBuffer<R>,
    ) -> Result<auth::Request, crate::client::runtime::RunError<Error, ScopedFault>> {
        let mut cursor = Cursor::new(signature.as_slice());
        let algorithm = cursor.text()?;
        cursor.string()?;
        if matches!(
            algorithm,
            "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com"
        ) {
            cursor.byte()?;
            cursor.word()?;
        }
        cursor.finish()?;
        let payload = self
            .bytes
            .as_slice()
            .get(self.request_offset..)
            .ok_or(Error::Inconsistent)?;
        let site = "client.auth.signed";
        let len = packet::length(site, &[payload.len(), 4, signature.len()])
            .map_err(crate::client::runtime::RunError::Runtime)?;
        let mut output =
            ScopedBuffer::try_with_capacity(scope, crate::scoped::ResourceClass::Secret, site, len)
                .map_err(crate::client::runtime::RunError::Runtime)?;
        output
            .try_extend_from_slice(scope, payload)
            .map_err(crate::client::runtime::RunError::Runtime)?;
        let len = u32::try_from(signature.len())
            .map_err(|_| crate::client::runtime::RunError::Runtime(ScopedFault::overflow(site)))?;
        output
            .try_extend_from_slice(scope, &len.to_be_bytes())
            .map_err(crate::client::runtime::RunError::Runtime)?;
        output
            .try_extend_from_slice(scope, signature.as_slice())
            .map_err(crate::client::runtime::RunError::Runtime)?;
        Ok(auth::Request {
            id,
            kind: auth::Kind::PublicKey,
            packet: output.erase(),
            continuation: true,
        })
    }
}

pub(super) fn algorithm(
    blob: &[u8],
    hash: Option<ssh_key::HashAlg>,
    certificate: bool,
) -> Result<&str, Error> {
    let mut cursor = Cursor::new(blob);
    let algorithm = cursor.text()?;
    if certificate != algorithm.ends_with("-cert-v01@openssh.com") {
        return Err(Error::Inconsistent);
    }
    Ok(if algorithm == "ssh-rsa" {
        match hash {
            Some(ssh_key::HashAlg::Sha256) => "rsa-sha2-256",
            Some(ssh_key::HashAlg::Sha512) => "rsa-sha2-512",
            None => algorithm,
            Some(_) => return Err(Error::UnknownAlgo),
        }
    } else {
        algorithm
    })
}

pub(super) fn probe<S: AdmissionScope>(
    scope: &S,
    id: u64,
    user: &str,
    algorithm: &str,
    key: &[u8],
) -> Result<auth::Request, ScopedFault> {
    let site = "client.auth.publickey";
    let len = packet::length(
        site,
        &[
            1,
            4,
            user.len(),
            4,
            14,
            4,
            9,
            1,
            4,
            algorithm.len(),
            4,
            key.len(),
        ],
    )?;
    let mut output = packet::Packet::new(scope, site, len)?;
    output.byte(scope, msg::USERAUTH_REQUEST)?;
    output.string(scope, user.as_bytes())?;
    output.string(scope, b"ssh-connection")?;
    output.string(scope, b"publickey")?;
    output.byte(scope, 0)?;
    output.string(scope, algorithm.as_bytes())?;
    output.string(scope, key)?;
    Ok(auth::Request {
        id,
        kind: auth::Kind::PublicKey,
        packet: output.finish().erase(),
        continuation: false,
    })
}

pub(super) fn ranges(bytes: &[u8]) -> Result<(usize, Range<usize>, Range<usize>), Error> {
    let mut cursor = Cursor::new(bytes);
    if cursor.byte()? != msg::USERAUTH_REQUEST {
        return Err(Error::Inconsistent);
    }
    cursor.text()?;
    if cursor.text()? != "ssh-connection" || cursor.text()? != "publickey" {
        return Err(Error::Inconsistent);
    }
    let flag = cursor.position();
    cursor.byte()?;
    let algorithm_len = cursor.word()? as usize;
    let algorithm_start = cursor.position();
    std::str::from_utf8(cursor.take(algorithm_len)?).map_err(|_| Error::Inconsistent)?;
    let key_len = cursor.word()? as usize;
    let key_start = cursor.position();
    cursor.take(key_len)?;
    cursor.finish()?;
    Ok((
        flag,
        algorithm_start..algorithm_start + algorithm_len,
        key_start..key_start + key_len,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::scoped::{
        ResourceClass,
        tests::{Scope, assert_no_allocations, assert_secret_release},
    };

    #[test]
    fn publickey_probe_denial_precedes_all_allocations() {
        let scope = Scope::new(0);
        let result =
            assert_no_allocations(|| probe(&scope, 1, "fixture", "ssh-ed25519", b"borrowed-key"));
        assert!(matches!(
            result,
            Err(ScopedFault {
                kind: crate::scoped::FaultKind::ByteBudget,
                site: "client.auth.publickey",
                ..
            })
        ));
        assert_eq!(scope.held(), 0);
    }

    #[test]
    fn cancelled_signing_request_wipes_full_capacity_after_late_holder() {
        let scope = Scope::new(usize::MAX);
        let probe = probe(&scope, 1, "fixture", "ssh-ed25519", b"borrowed-key").unwrap();
        let mut bytes = ScopedBuffer::try_with_capacity(
            &scope,
            ResourceClass::Secret,
            "test.sign.input",
            12 + probe.packet.as_slice().len() + 37,
        )
        .unwrap();
        bytes
            .try_extend_from_slice(&scope, &8u32.to_be_bytes())
            .unwrap();
        bytes.try_extend_from_slice(&scope, b"session!").unwrap();
        bytes
            .try_extend_from_slice(&scope, probe.packet.as_slice())
            .unwrap();
        let len = bytes.len();
        bytes.try_resize(&scope, bytes.capacity(), 0xA7).unwrap();
        bytes.truncate(len);
        drop(probe);
        assert_secret_release(&scope, bytes, |bytes| {
            let request = ScopedSignRequest::<crate::scoped::tests::Reservation>::from_reply(
                bytes.erase(),
                12,
            )
            .unwrap();
            assert_eq!(request.algorithm(), "ssh-ed25519");
            assert_eq!(request.public_key_blob(), b"borrowed-key");
            let late = request.root().try_clone().unwrap();
            drop(request);
            assert!(scope.held() > 0);
            drop(late);
        });
        assert_eq!(scope.held(), 0);
    }
}
