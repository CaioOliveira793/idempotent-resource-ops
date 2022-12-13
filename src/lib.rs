use core::{cmp, fmt, time::Duration};

#[derive(Debug, PartialEq, Eq)]
pub enum ConditionalHeader<Etag, DateTime> {
    IfNoneMatch,
    IfMatch(Etag),
    IfUnmodifiedSince(DateTime),
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdempotencyError {
    PreconditionFailed,
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

    /// Accept Modified
    ///
    /// The `Accept-Modified-After` header is present and was successfully verified.
    AcceptModified,
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdempotencyError::PreconditionFailed => f.write_str("Precondition Failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdempotencyError {}

pub trait ResourceState {
    type Etag: PartialEq<Self::Etag>;
    type DateTime;

    fn created(&self) -> Self::DateTime;
    fn updated(&self) -> Option<Self::DateTime>;
    fn etag(&self) -> Self::Etag;
}

pub const ACCEPT_MODIFIED_AFTER_DURATION_LIMIT: Duration = Duration::from_secs(60 * 60 * 24); // 24h

pub fn verify_idempotency<Resource, DateTime>(
    resource: Option<&Resource>,
    conditional_header: &ConditionalHeader<Resource::Etag, DateTime>,
    accept_modified_after: Option<&DateTime>,
) -> Result<IdempotencySuccess, IdempotencyError>
where
    Resource: ResourceState<DateTime = DateTime>,
    DateTime: cmp::PartialOrd,
{
    match conditional_header {
        ConditionalHeader::IfNoneMatch => verify_if_none_match(resource, accept_modified_after),
        ConditionalHeader::IfMatch(etag) => verify_if_match(resource, etag, accept_modified_after),
        ConditionalHeader::IfUnmodifiedSince(unmodified) => {
            verify_if_unmodified_since(resource, unmodified, accept_modified_after)
        }
    }
}

pub fn verify_if_none_match<Resource, DateTime>(
    resource: Option<&Resource>,
    accept_modified_after: Option<&DateTime>,
) -> Result<IdempotencySuccess, IdempotencyError>
where
    Resource: ResourceState<DateTime = DateTime>,
    DateTime: cmp::PartialOrd,
{
    match (resource, accept_modified_after) {
        (None, _) => return Ok(IdempotencySuccess::PreconditionMeet),
        (Some(_), None) => Err(IdempotencyError::PreconditionFailed),
        (Some(resource), Some(accept_date)) if *accept_date <= resource.created() => {
            Ok(IdempotencySuccess::AcceptModified)
        }
        (Some(_), Some(_)) => Err(IdempotencyError::PreconditionFailed),
    }
}

pub fn verify_if_match<Resource, Etag, DateTime>(
    resource: Option<&Resource>,
    etag: &Etag,
    accept_modified_after: Option<&DateTime>,
) -> Result<IdempotencySuccess, IdempotencyError>
where
    Resource: ResourceState<DateTime = DateTime>,
    Etag: PartialEq<Resource::Etag> + ?Sized,
    DateTime: cmp::PartialOrd,
{
    match resource {
        Some(resource) if *etag == resource.etag() => Ok(IdempotencySuccess::PreconditionMeet),
        Some(resource)
            if matches!(
                (accept_modified_after, resource.updated()),
                (Some(accept_date), Some(modified))
                if *accept_date <= modified
            ) =>
        {
            Ok(IdempotencySuccess::AcceptModified)
        }
        Some(_) | None => Err(IdempotencyError::PreconditionFailed),
    }
}

pub fn verify_if_unmodified_since<Resource, DateTime>(
    resource: Option<&Resource>,
    unmodified: &DateTime,
    accept_modified_after: Option<&DateTime>,
) -> Result<IdempotencySuccess, IdempotencyError>
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

            if matches!(accept_modified_after, Some(accept_date) if *accept_date <= modified) {
                return Ok(IdempotencySuccess::AcceptModified);
            }

            Err(IdempotencyError::PreconditionFailed)
        }
        None => Err(IdempotencyError::PreconditionFailed),
    }
}

#[cfg(test)]
mod test_lib {
    use core::fmt::{self, Write};

    use time::OffsetDateTime;

    use crate::ResourceState;

    #[derive(PartialEq)]
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

    use crate::{test_lib::Post, verify_if_none_match, IdempotencyError, IdempotencySuccess};

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
            Ok(IdempotencySuccess::AcceptModified)
        );

        assert_eq!(
            verify_if_none_match(Some(&resource), Some(&resource.created)),
            Ok(IdempotencySuccess::AcceptModified)
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
            Err(IdempotencyError::PreconditionFailed)
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
            Err(IdempotencyError::PreconditionFailed)
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
        verify_if_match, IdempotencyError, IdempotencySuccess, ResourceState,
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
            Ok(IdempotencySuccess::AcceptModified)
        );

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &Etag::new(9, 2),
                Some(&resource.updated.expect("Expect updated resource"))
            ),
            Ok(IdempotencySuccess::AcceptModified)
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
            Err(IdempotencyError::PreconditionFailed)
        );

        assert_eq!(
            verify_if_match(
                Some(&resource),
                &Etag::new(12, 2),
                Some(&OffsetDateTime::now_utc().sub(Duration::from_millis(10)))
            ),
            Err(IdempotencyError::PreconditionFailed)
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
            Err(IdempotencyError::PreconditionFailed)
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
            Err(IdempotencyError::PreconditionFailed)
        );

        assert_eq!(
            verify_if_match(None as Option<&Post>, &Etag::new(1, 1), None),
            Err(IdempotencyError::PreconditionFailed)
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

    use crate::{test_lib::Post, verify_if_unmodified_since, IdempotencyError, IdempotencySuccess};

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
            "Expect meet precodition of unmodified resource since the last updated time without accept modified after"
        );

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &updated_time,
                None,
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource at exact updated time without accept modified after"
        );

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &after_updated_time,
                Some(&OffsetDateTime::now_utc().add(Duration::from_secs(60))),
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource since the last updated time with unused accept modified after"
        );

        assert_eq!(
            verify_if_unmodified_since(
                Some(&resource),
                &updated_time,
                Some(&OffsetDateTime::now_utc().add(Duration::from_secs(60))),
            ),
            Ok(IdempotencySuccess::PreconditionMeet),
            "Expect meet precodition of unmodified resource at exact updated time with unused accept modified after"
        );
    }

    #[test]
    fn ok_some_resource_modified_since_and_accept_modified_after() {
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
            Ok(IdempotencySuccess::AcceptModified)
        );

        assert_eq!(
            verify_if_unmodified_since(Some(&resource), &before_updated_time, Some(&updated_time)),
            Ok(IdempotencySuccess::AcceptModified)
        );
    }

    #[test]
    fn err_some_resource_modified_since_and_not_accept_modified_after() {
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
            Err(IdempotencyError::PreconditionFailed),
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
            Err(IdempotencyError::PreconditionFailed),
        );
    }
}
