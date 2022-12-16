#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::unwrap_used)]

//! Implementation of resource verification based on the [HTTP Conditional headers
//! ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Conditional_requests#conditional_headers)
//! and other custom headers to provide stateless idempotent requests.
//!
//! # How does idempotency is achieved?
//!
//! The request idempotency is achieved by using the conditional headers
//! [`If-None-Match`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match),
//! [`If-Match`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match) and
//! [`If-Unmodified-Since`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Unmodified-Since)
//! to avoid common problems mutating resources, like the [lost update](https://www.w3.org/1999/04/Editing/),
//! and ensuring that the request is only processed once.
//!
//! With the conditional headers, the server state can be preserved in case of duplicated request, althoght,
//! a client that encounters a timeout error and make a retry receiving a precondition failed cannot easily
//! know if the server already processed the request.
//!
//! ## `Accept-Modified-Since` header
//!
//! For a server and client consensus, a custom header `Accept-Modified-Since` is supported, verfing if
//! the request could be a retry of a call that already modified the resource in case the coditional header
//! does not match. This header can be used by the client in every request that could accept a resource
//! modified after the prevoius **potential** update.
//!
//! ### Usage
//!
//! In every request the client issues, `Accept-Modified-Since` header **should** be set to the first
//! time the client is sending the request, so in case the response does not arrive, a retry could be
//! send with `Accept-Modified-Since` as the **same as the first attempt**.
//!
//! Make the first attempt in Tue, 13 Dec 2022 17:08:09
//!
//! ```txt
//! PUT /blog/post HTTP/1.1
//! If-Match: #82c8d70155524b43a5652e04ad27cadf~V0000000000000003
//! Accept-Modified-Since: 2022-12-13T17:08:09.141Z
//! ...
//! ```
//!
//! Timeout or some network error
//!
//! ```txt
//! HTTP/1.1 408 Request Timeout
//! Date: Tue, 13 Dec 2022 17:08:10 GMT
//! ...
//! ```
//!
//! Retry the request after some time with **same Accept-Modified-Since header**
//!
//! ```txt
//! PUT /blog/post HTTP/1.1
//! If-Match: #82c8d70155524b43a5652e04ad27cadf~V0000000000000003
//! Accept-Modified-Since: 2022-12-13T17:08:09.141Z
//! ...
//! ```
//!
//! By using `Accept-Modified-Since` with the first attempt date, the server can verify if the resource
//! was already modified, returning a success response.
//!
//! ### Safety
//!
//! However, in case the first request is not processed and a concurrent update is made in the resource,
//! retring with `Accept-Modified-Since` will cause the server to accept the retry **not processing** the
//! request and returning a success response.
//!
//! Although the header semantics still preserved, if a request **must be guaranteed** to be applied, the
//! `Accept-Modified-Since` is **not recommended**.
//!
//! ## Creating resources
//!
//! Create operations are not idempotent calls by default, but when some rules are applied to these
//! operations they can become idempotent. For example, pushing a value in a Vec vs. inserting a value in
//! a Set.
//!
//! ```
//! let mut vec = Vec::new();
//! vec.push(1);
//! vec.push(2);
//! vec.push(2);
//!
//! assert_eq!(vec.len(), 3);
//! ```
//!
//! ```
//! # use std::collections::HashSet;
//! let mut set = HashSet::new();
//! set.insert(1);
//! set.insert(2);
//! set.insert(2);
//!
//! assert_eq!(set.len(), 2);
//! ```
//!
//! Based on this example, using unique value for all resources of the same type can make a create operation
//! idempotent.
//!
//! Therefore, by generating resource IDs in the client, a create operation is guaranteed to produce only
//! one resource if repeated multiple times.
//!
//! ## ID colisions
//!
//! Creating resources with client generated IDs can possibly lead to colisions. For that reason, always
//! validate if there is a resource with the same ID is a behaviour enforced by the `If-None-Match: *` header.
//!
//! However, with `Accept-Modified-Since`, a request could misuse the header to allow resources created
//! with a greater date range.
//!
//! ```txt
//! PUT /blog/post HTTP/1.1
//! If-Match: #82c8d70155524b43a5652e04ad27cadf~V0000000000000003
//! Accept-Modified-Since: 2000-12-13T17:08:09.141Z
//! ```
//!
//! In order to prevent this exploit, the `Accept-Modified-Since` date can be lower bound to the moment
//! the request was made minus some duration allowed to verify possible retries (`$time::now() -
//! ACCEPT_MODIFIED_SINCE_DURATION_LIMIT`), resulting in a limited range of resources that may have a ID
//! colision with the one being created.
//!
//! Choosing a duration for `ACCEPT_MODIFIED_SINCE_DURATION_LIMIT` should consider the ID entropy and how
//! many resources are created through the entire duration. As a safe configuration, a **UUID v4** and a
//! duration of **24 hours** should be a good standard for most of the use cases.
//!
//! ## HTTP create request
//!
//! In HTTP APIs there are 2 possible ways to implement create semantics:
//!
//! - POST
//! - PUT with If-None-Match
//!
//! Bouth of then need to pass the resource ID in the request to be idempotent, however, to favor
//! standardization of API endpoints, PUT with If-None-Match header could be prefered for idempotent calls
//! and POST for non-idempotent calls.

use core::{cmp, fmt};

/// HTTP Conditional Header
///
/// [Conditional headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Conditional_requests#conditional_headers)
/// used in the idempotency verification.
#[derive(Debug, PartialEq, Eq)]
pub enum ConditionalHeader<Etag, DateTime> {
    /// [If-None-Match](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match)
    ///
    /// Allow the request only if the resource does not exists.
    ///
    /// Used to avoid ID colisions creating resources.
    IfNoneMatch,

    /// [If-Match](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match)
    ///
    /// This header will allow the request to proceed only if the resource match with the specified Etag.
    ///
    /// Used in resource updates to avoid the [lost update problem](https://www.w3.org/1999/04/Editing/).
    IfMatch(Etag),

    /// [If-Unmodified-Since](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Unmodified-Since)
    ///
    /// Accept the request if the resource has not been modified after the date specified.
    IfUnmodifiedSince(DateTime),
}

impl<Etag, DateTime> fmt::Display for ConditionalHeader<Etag, DateTime>
where
    Etag: fmt::Display,
    DateTime: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConditionalHeader::IfNoneMatch => f.write_str("If-None-Match: *"),
            ConditionalHeader::IfMatch(etag) => {
                write!(f, "If-Match: {etag}")
            }
            ConditionalHeader::IfUnmodifiedSince(date) => write!(f, "If-Unmodified-Since: {date}"),
        }
    }
}

/// Idempotency Success
///
/// Conditions in which the idempotency verification succeeded.
#[derive(Debug, PartialEq, Eq)]
pub enum IdempotencySuccess {
    /// Precondition Meet
    ///
    /// The precondition verification has passed and is safe to handle the request.
    PreconditionMeet,

    /// Accept Modified Since
    ///
    /// The `Accept-Modified-Since` custom header is present and was successfully verified.
    AcceptedModifiedSince,
}

impl fmt::Display for IdempotencySuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdempotencySuccess::PreconditionMeet => f.write_str("Precondition Meet"),
            IdempotencySuccess::AcceptedModifiedSince => f.write_str("Accepted Modified Since"),
        }
    }
}

/// Precondition Failed
///
/// The precondition of a conditional header is not satisfied.
/// This error maps directly to [HTTP 412 Status code](https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Status/412)
#[derive(Debug, PartialEq, Eq)]
pub struct PreconditionFailed;

impl PreconditionFailed {
    /// HTTP Status Code
    pub const fn status_code() -> u16 {
        412
    }
}

impl fmt::Display for PreconditionFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Precondition Failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PreconditionFailed {}

/// Resource state metadata information
pub trait ResourceState {
    /// Resource [Etag](https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/ETag) type
    type Etag: PartialEq<Self::Etag>;

    /// Date and time type
    type DateTime;

    /// Moment that the resource was created.
    fn created(&self) -> Self::DateTime;

    /// Moment that the resource was updated.
    ///
    /// None is returned in case the resource was never updated.
    fn updated(&self) -> Option<Self::DateTime>;

    /// Resource [Etag](https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/ETag)
    fn etag(&self) -> Self::Etag;
}

pub fn verify_idempotency<Resource, DateTime>(
    resource: Option<&Resource>,
    conditional_header: &ConditionalHeader<Resource::Etag, DateTime>,
    accept_modified_since: Option<&DateTime>,
) -> Result<IdempotencySuccess, PreconditionFailed>
where
    Resource: ResourceState<DateTime = DateTime>,
    DateTime: cmp::PartialOrd,
{
    match conditional_header {
        ConditionalHeader::IfNoneMatch => verify_if_none_match(resource, accept_modified_since),
        ConditionalHeader::IfMatch(etag) => verify_if_match(resource, etag, accept_modified_since),
        ConditionalHeader::IfUnmodifiedSince(unmodified) => {
            verify_if_unmodified_since(resource, unmodified, accept_modified_since)
        }
    }
}

pub fn verify_if_none_match<Resource, DateTime>(
    resource: Option<&Resource>,
    accept_modified_since: Option<&DateTime>,
) -> Result<IdempotencySuccess, PreconditionFailed>
where
    Resource: ResourceState<DateTime = DateTime>,
    DateTime: cmp::PartialOrd,
{
    match (resource, accept_modified_since) {
        (None, _) => Ok(IdempotencySuccess::PreconditionMeet),
        (Some(_), None) => Err(PreconditionFailed),
        (Some(resource), Some(accept_date)) if *accept_date <= resource.created() => {
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        }
        (Some(_), Some(_)) => Err(PreconditionFailed),
    }
}

pub fn verify_if_match<Resource, Etag, DateTime>(
    resource: Option<&Resource>,
    etag: &Etag,
    accept_modified_since: Option<&DateTime>,
) -> Result<IdempotencySuccess, PreconditionFailed>
where
    Resource: ResourceState<DateTime = DateTime>,
    Etag: PartialEq<Resource::Etag> + ?Sized,
    DateTime: cmp::PartialOrd,
{
    match resource {
        Some(resource) if *etag == resource.etag() => Ok(IdempotencySuccess::PreconditionMeet),
        Some(resource)
            if matches!(
                (accept_modified_since, resource.updated()),
                (Some(accept_date), Some(modified))
                if *accept_date <= modified
            ) =>
        {
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        }
        Some(_) | None => Err(PreconditionFailed),
    }
}

pub fn verify_if_unmodified_since<Resource, DateTime>(
    resource: Option<&Resource>,
    unmodified: &DateTime,
    accept_modified_since: Option<&DateTime>,
) -> Result<IdempotencySuccess, PreconditionFailed>
where
    Resource: ResourceState<DateTime = DateTime>,
    DateTime: cmp::PartialOrd,
{
    match resource {
        Some(resource) => {
            let modified = resource.updated().unwrap_or(resource.created());
            if *unmodified >= modified {
                return Ok(IdempotencySuccess::PreconditionMeet);
            }

            if matches!(accept_modified_since, Some(accept_date) if *accept_date <= modified) {
                return Ok(IdempotencySuccess::AcceptedModifiedSince);
            }

            Err(PreconditionFailed)
        }
        None => Err(PreconditionFailed),
    }
}

#[cfg(test)]
mod test_lib {
    use core::fmt::{self, Write};

    use time::OffsetDateTime;

    use crate::ResourceState;

    #[derive(PartialEq, Eq)]
    pub struct Etag {
        id: u64,
        version: u32,
    }

    impl Etag {
        pub fn new(id: u64, version: u32) -> Self {
            Self { id, version }
        }
    }

    impl core::fmt::Display for Etag {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_char('#')?;
            write!(f, "{:032X}", self.id)?;
            f.write_str("~V")?;
            write!(f, "{:016X}", self.version)
        }
    }

    pub struct Post {
        pub id: u64,
        pub created: OffsetDateTime,
        pub updated: Option<OffsetDateTime>,
        pub version: u32,
        pub body: String,
    }

    impl ResourceState for Post {
        type Etag = Etag;
        type DateTime = OffsetDateTime;

        fn created(&self) -> Self::DateTime {
            self.created
        }

        fn updated(&self) -> Option<Self::DateTime> {
            self.updated
        }

        fn etag(&self) -> Self::Etag {
            Etag::new(self.id, self.version)
        }
    }

    #[test]
    fn etag_display() {
        let etag = Etag::new(1, 3);

        assert_eq!(
            &etag.to_string(),
            "#00000000000000000000000000000001~V0000000000000003"
        );
    }
}

#[cfg(test)]
mod test_if_none_match {
    use core::{
        ops::{Add, Sub},
        time::Duration,
    };

    use time::OffsetDateTime;

    use crate::{test_lib::Post, verify_if_none_match, IdempotencySuccess, PreconditionFailed};

    #[test]
    fn ok_none_resource() {
        assert_eq!(
            verify_if_none_match(None as Option<&Post>, Some(&OffsetDateTime::now_utc())),
            Ok(IdempotencySuccess::PreconditionMeet)
        );

        assert_eq!(
            verify_if_none_match(None as Option<&Post>, None),
            Ok(IdempotencySuccess::PreconditionMeet)
        );
    }

    #[test]
    fn ok_some_resource_created_after_accept_date() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: None,
            version: 1,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_none_match(
                Some(&resource),
                Some(&resource.created.sub(Duration::from_millis(10)))
            ),
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        );

        assert_eq!(
            verify_if_none_match(Some(&resource), Some(&resource.created)),
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        );
    }

    #[test]
    fn error_some_resource_created_before_accept_date() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: None,
            version: 1,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_none_match(
                Some(&resource),
                Some(&resource.created.add(Duration::from_millis(10)))
            ),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn error_some_resource_created_and_none_accept_date() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: None,
            version: 1,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_none_match(Some(&resource), None),
            Err(PreconditionFailed)
        );
    }
}

#[cfg(test)]
mod test_if_match {
    use core::{
        ops::{Add, Sub},
        time::Duration,
    };

    use time::OffsetDateTime;

    use crate::{
        test_lib::{Etag, Post},
        verify_if_match, IdempotencySuccess, PreconditionFailed, ResourceState,
    };

    #[test]
    fn ok_some_updated_resource_matching_etag() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: Some(OffsetDateTime::now_utc().add(Duration::from_millis(10))),
            version: 4,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_match(Some(&resource), &resource.etag(), None),
            Ok(IdempotencySuccess::PreconditionMeet)
        );

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &resource.etag(),
                Some(&OffsetDateTime::now_utc())
            ),
            Ok(IdempotencySuccess::PreconditionMeet)
        );
    }

    #[test]
    fn ok_some_resource_not_updated_matching_etag() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: None,
            version: 1,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_match(Some(&resource), &resource.etag(), None),
            Ok(IdempotencySuccess::PreconditionMeet)
        );

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &resource.etag(),
                Some(&OffsetDateTime::now_utc())
            ),
            Ok(IdempotencySuccess::PreconditionMeet)
        );
    }

    #[test]
    fn ok_some_resource_not_matching_etag_and_updated_after_accept_date() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: Some(OffsetDateTime::now_utc().add(Duration::from_millis(10))),
            version: 2,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &Etag::new(36, 12),
                Some(
                    &resource
                        .updated
                        .expect("Expect updated resource")
                        .sub(Duration::from_millis(10))
                )
            ),
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        );

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &Etag::new(9, 2),
                Some(&resource.updated.expect("Expect updated resource"))
            ),
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        );
    }

    #[test]
    fn error_some_resource_not_matching_etag_and_not_updated() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: None,
            version: 1,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_match(Some(&resource), &Etag::new(45, 12), None),
            Err(PreconditionFailed)
        );

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &Etag::new(12, 2),
                Some(&OffsetDateTime::now_utc().sub(Duration::from_millis(10)))
            ),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn error_some_resource_not_matching_etag_and_updated_before_accept_date() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: Some(OffsetDateTime::now_utc().add(Duration::from_millis(10))),
            version: 1,
            body: "Great post".into(),
        };

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &Etag::new(87, 91),
                Some(
                    &resource
                        .updated
                        .expect("Expect updated resource")
                        .add(Duration::from_millis(10))
                )
            ),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn error_none_resource() {
        assert_eq!(
            verify_if_match(
                None as Option<&Post>,
                &Etag::new(1, 1),
                Some(&OffsetDateTime::now_utc())
            ),
            Err(PreconditionFailed)
        );

        assert_eq!(
            verify_if_match(None as Option<&Post>, &Etag::new(1, 1), None),
            Err(PreconditionFailed)
        );
    }
}

#[cfg(test)]
mod test_if_unmodified_since {
    use core::{
        ops::{Add, Sub},
        time::Duration,
    };

    use time::OffsetDateTime;

    use crate::{
        test_lib::Post, verify_if_unmodified_since, IdempotencySuccess, PreconditionFailed,
    };

    #[test]
    fn ok_some_resource_unmodified_since() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: Some(OffsetDateTime::now_utc()),
            version: 3,
            body: "Great post".into(),
        };

        let updated_time = resource.updated.expect("Expect updated resource");
        let after_updated_time = updated_time.add(Duration::from_millis(10));

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &after_updated_time,
                None,
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource since the last updated time without accept modified since"
        );

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &updated_time,
                None,
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource at exact updated time without accept modified since"
        );

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &after_updated_time,
                Some(&OffsetDateTime::now_utc().add(Duration::from_secs(60))),
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource since the last updated time with unused accept modified since"
        );

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &updated_time,
                Some(&OffsetDateTime::now_utc().add(Duration::from_secs(60))),
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource at exact updated time with unused accept modified since"
        );
    }

    #[test]
    fn ok_some_resource_modified_since_and_accept_modified_since() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: Some(OffsetDateTime::now_utc()),
            version: 3,
            body: "Great post".into(),
        };

        let updated_time = resource.updated.expect("Expect updated resource");
        let before_updated_time = updated_time.sub(Duration::from_millis(10));

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &before_updated_time,
                Some(&before_updated_time),
            ),
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        );

        assert_eq!(
            verify_if_unmodified_since(Some(&resource), &before_updated_time, Some(&updated_time)),
            Ok(IdempotencySuccess::AcceptedModifiedSince)
        );
    }

    #[test]
    fn err_some_resource_modified_since_and_not_accept_modified_since() {
        let resource = Post {
            id: 1,
            created: OffsetDateTime::now_utc(),
            updated: Some(OffsetDateTime::now_utc()),
            version: 3,
            body: "Great post".into(),
        };

        let updated_time = resource.updated.expect("Expect updated resource");
        let before_updated_time = updated_time.sub(Duration::from_millis(10));
        let after_updated_time = updated_time.add(Duration::from_millis(10));

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &before_updated_time,
                Some(&after_updated_time),
            ),
            Err(PreconditionFailed),
        );
    }

    #[test]
    fn err_none_resource() {
        assert_eq!(
            verify_if_unmodified_since(
                None as Option<&Post>,
                &OffsetDateTime::now_utc(),
                Some(&OffsetDateTime::now_utc()),
            ),
            Err(PreconditionFailed),
        );
    }
}
