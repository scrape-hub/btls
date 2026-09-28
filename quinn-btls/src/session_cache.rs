use crate::error::Result;
use crate::{Error, QuicSslSession};
use btls::ssl::{SslContextRef, SslSession};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use lru::LruCache;
use quinn_proto::{transport_parameters::TransportParameters, Side};
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Mutex, PoisonError};

/// A client-side Session cache for the BoringSSL crypto provider.
///
/// A cache may keep more than one session per key: [SimpleCache] keeps the two newest. The client
/// keeps the sessions of each QUIC version under a key of their own, see [session_cache_key].
pub trait SessionCache: Send + Sync {
    /// Adds the given value to the session cache.
    fn put(&self, key: Bytes, value: Bytes);

    /// Returns the newest cached session, if it exists.
    fn get(&self, key: Bytes) -> Option<Bytes>;

    /// Removes the newest cached session and returns it, if it exists.
    ///
    /// A client takes the session out of the cache when it sets it on a new connection: QUIC
    /// runs TLS 1.3, whose session tickets a client uses only once (RFC 8446, appendix C.4). The
    /// connection stores the tickets the server sends it with [Self::put]. BoringSSL decides
    /// only when the handshake starts whether it offers the session, and drops one it cannot
    /// offer, e.g. because it has expired, which could not be used later either.
    ///
    /// The default implementation calls [Self::get] and then [Self::remove], which suits a
    /// cache with one session per key. Implementations that keep more, or that can do both at
    /// once, should override it; doing it at once ensures that connections started at the same
    /// time never offer the same ticket.
    fn take(&self, key: Bytes) -> Option<Bytes> {
        let value = self.get(key.clone())?;
        self.remove(key);
        Some(value)
    }

    /// Removes the cached sessions, if they exist.
    fn remove(&self, key: Bytes);

    /// Removes all entries from the cache.
    fn clear(&self);
}

/// The [SessionCache] key of the sessions of `server_name` for QUIC `version`: the server name
/// itself for version 1, followed by a zero byte and the version in four bytes (big endian) for
/// others. A session ticket is only good for the version of the connection that received it
/// (RFC 9369, section 5), after compatible version negotiation the negotiated one, and a client
/// only offers it on a connection that starts with that version.
pub fn session_cache_key(server_name: &str, version: u32) -> Bytes {
    if version == 1 {
        return Bytes::copy_from_slice(server_name.as_bytes());
    }
    let mut key = BytesMut::with_capacity(server_name.len() + 5);
    key.put_slice(server_name.as_bytes());
    key.put_u8(0);
    key.put_u32(version);
    key.freeze()
}

/// A utility for combining an [SslSession] and server [TransportParameters] as a
/// [SessionCache] entry.
pub struct Entry {
    pub session: SslSession,
    pub params: TransportParameters,
}

impl Entry {
    /// Encodes this [Entry] into a [SessionCache] value.
    pub fn encode(&self) -> Result<Bytes> {
        let mut out = BytesMut::with_capacity(2048);

        // Split the buffer in two: the length prefix buffer and the encoded session buffer.
        // This will be O(1) as both will refer to the same underlying buffer.
        let mut encoded = out.split_off(8);

        // Store the session in the second buffer.
        self.session.encode(&mut encoded)?;

        // Go back and write the length to the first buffer.
        out.put_u64(encoded.len() as u64);

        // Unsplit to merge the two buffers back together. This will be O(1) since
        // the buffers are already contiguous in memory.
        out.unsplit(encoded);

        // Now add the transport parameters.
        out.reserve(128);
        let mut encoded = out.split_off(out.len() + 8);
        self.params.write(&mut encoded);
        out.put_u64(encoded.len() as u64);
        out.unsplit(encoded);

        Ok(out.freeze())
    }

    /// Decodes a [SessionCache] value into an [Entry].
    pub fn decode(ctx: &SslContextRef, mut encoded: Bytes) -> Result<Self> {
        // Decode the session.
        let len = encoded.get_u64() as usize;
        let mut encoded_session = encoded.split_to(len);
        let session = SslSession::decode(ctx, &mut encoded_session)?;

        // Decode the transport parameters.
        let len = encoded.get_u64() as usize;
        let mut encoded_params = encoded.split_to(len);
        let params = TransportParameters::read(Side::Client, &mut encoded_params).map_err(|e| {
            Error::invalid_input(format!("failed parsing cached transport parameters: {e:?}"))
        })?;

        Ok(Self { session, params })
    }
}

/// A [SessionCache] implementation that will never cache anything. Requires no storage.
pub struct NoSessionCache;

impl SessionCache for NoSessionCache {
    fn put(&self, _: Bytes, _: Bytes) {}

    fn get(&self, _: Bytes) -> Option<Bytes> {
        None
    }

    fn remove(&self, _: Bytes) {}

    fn clear(&self) {}
}

/// The number of sessions [SimpleCache] keeps per key, as Chrome's QUIC session cache does
/// (`QuicClientSessionCache`). Servers commonly send two tickets per connection.
const SESSIONS_PER_KEY: usize = 2;

/// A [SessionCache] that keeps the two newest sessions of the `num_entries` most recently used
/// keys. [SessionCache::take] hands out the newest session first, so two connections started
/// before new tickets arrive both resume.
pub struct SimpleCache {
    /// The sessions of each key, newest first.
    cache: Mutex<LruCache<Bytes, VecDeque<Bytes>>>,
}

impl SimpleCache {
    pub fn new(num_entries: usize) -> Self {
        SimpleCache {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(num_entries).unwrap())),
        }
    }
}

impl SessionCache for SimpleCache {
    fn put(&self, key: Bytes, value: Bytes) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let sessions = cache.get_or_insert_mut(key, VecDeque::new);
        sessions.push_front(value);
        sessions.truncate(SESSIONS_PER_KEY);
    }

    fn get(&self, key: Bytes) -> Option<Bytes> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)?
            .front()
            .cloned()
    }

    fn take(&self, key: Bytes) -> Option<Bytes> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let sessions = cache.get_mut(&key)?;
        let value = sessions.pop_front();
        if sessions.is_empty() {
            cache.pop(&key);
        }
        value
    }

    fn remove(&self, key: Bytes) {
        let _ = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop(&key);
    }

    fn clear(&self) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_cache_hands_out_the_two_newest_sessions_newest_first() {
        let cache = SimpleCache::new(8);
        let key = Bytes::from_static(b"example.com");
        for session in ["first", "second", "third"] {
            cache.put(key.clone(), Bytes::from(session));
        }
        assert_eq!(cache.get(key.clone()).as_deref(), Some(&b"third"[..]));
        assert_eq!(cache.take(key.clone()).as_deref(), Some(&b"third"[..]));
        assert_eq!(cache.take(key.clone()).as_deref(), Some(&b"second"[..]));
        assert_eq!(cache.take(key.clone()), None);

        cache.put(key.clone(), Bytes::from("fourth"));
        cache.put(key.clone(), Bytes::from("fifth"));
        cache.remove(key.clone());
        assert_eq!(cache.get(key), None);
    }
}
