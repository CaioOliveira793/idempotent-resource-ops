use core::time::Duration;

use time::OffsetDateTime;

#[derive(Debug, PartialEq, Eq)]
pub enum ConditionalHeader<Etag> {
    IfNoneMatch,
    IfMatch(Etag),
    IfUnmodifiedSince(OffsetDateTime),
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdempotencyError {
    PreconditionFailed,
}

impl core::fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdempotencyError::PreconditionFailed => f.write_str("Precondition Failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdempotencyError {}

pub trait ResourceState {
    type Etag: PartialEq<Self::Etag>;

    fn created(&self) -> OffsetDateTime;
    fn updated(&self) -> Option<OffsetDateTime>;
    fn etag(&self) -> Self::Etag;
}

pub trait ResourceProducer<Resource> {
    fn could_reproduce_resource(&self, resource: &Resource) -> bool;
}

pub const ACCEPT_MODIFIED_AFTER_DURATION_LIMIT: Duration = Duration::from_secs(60 * 60 * 24); // 24h

pub fn verify_idempotency<R>(
    resource: Option<&R>,
    conditional_header: &ConditionalHeader<R::Etag>,
    accept_modified_after: Option<&OffsetDateTime>,
) -> Result<(), IdempotencyError>
where
    R: ResourceState,
{
    match conditional_header {
        ConditionalHeader::IfNoneMatch => {
            return verify_if_none_match(resource, accept_modified_after);
        }
        ConditionalHeader::IfMatch(etag) => {
            return verify_if_match(resource, etag, accept_modified_after);
        }
        ConditionalHeader::IfUnmodifiedSince(unmodified) => {
            return verify_if_unmodified_since(resource, unmodified, accept_modified_after);
        }
    }
}

fn verify_if_none_match<R>(
    resource: Option<&R>,
    accept_modified_after: Option<&OffsetDateTime>,
) -> Result<(), IdempotencyError>
where
    R: ResourceState,
{
    match (resource, accept_modified_after) {
        (None, _) => return Ok(()),
        (Some(_), None) => {
            return Err(IdempotencyError::PreconditionFailed);
        }
        (Some(resource), Some(accept_date)) => {
            if *accept_date <= resource.created() {
                return Ok(());
            } else {
                return Err(IdempotencyError::PreconditionFailed);
            }
        }
    }
}

fn verify_if_match<R, E>(
    resource: Option<&R>,
    etag: &E,
    accept_modified_after: Option<&OffsetDateTime>,
) -> Result<(), IdempotencyError>
where
    R: ResourceState,
    E: PartialEq<R::Etag> + ?Sized,
{
    match resource {
        Some(resource) => {
            if *etag != resource.etag() {
                if let (Some(accept_date), Some(modified)) =
                    (accept_modified_after, resource.updated())
                {
                    if *accept_date <= modified {
                        return Ok(());
                    }
                }
                return Err(IdempotencyError::PreconditionFailed);
            }
            Ok(())
        }
        None => Err(IdempotencyError::PreconditionFailed),
    }
}

fn verify_if_unmodified_since<R>(
    resource: Option<&R>,
    unmodified: &OffsetDateTime,
    accept_modified_after: Option<&OffsetDateTime>,
) -> Result<(), IdempotencyError>
where
    R: ResourceState,
{
    match resource {
        Some(resource) => {
            let modified = resource.updated().unwrap_or(resource.created());
            if *unmodified >= modified {
                if matches!(accept_modified_after, Some(accept_date) if *accept_date <= modified) {
                    return Ok(());
                }
                return Err(IdempotencyError::PreconditionFailed);
            }
            Ok(())
        }
        None => Err(IdempotencyError::PreconditionFailed),
    }
}

#[cfg(test)]
mod test {
    use core::fmt::Write;

    use time::OffsetDateTime;

    use crate::ResourceState;

    #[derive(PartialEq)]
    struct Etag {
        id: u64,
        version: u32,
    }

    impl Etag {
        pub fn new(id: u64, version: u32) -> Self {
            Self { id, version }
        }
    }

    impl core::fmt::Display for Etag {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_char('#')?;
            write!(f, "{:032X}", self.id)?;
            f.write_str("~V")?;
            write!(f, "{:016X}", self.version)
        }
    }

    struct User {
        id: u64,
        created: OffsetDateTime,
        updated: Option<OffsetDateTime>,
        version: u32,
    }

    impl ResourceState for User {
        type Etag = Etag;

        fn created(&self) -> OffsetDateTime {
            self.created
        }

        fn updated(&self) -> Option<OffsetDateTime> {
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

    mod test_if_none_match {
        use core::{
            ops::{Add, Sub},
            time::Duration,
        };

        use time::OffsetDateTime;

        use crate::{test::User, verify_if_none_match, IdempotencyError};

        #[test]
        fn ok_none_resource() {
            assert_eq!(
                verify_if_none_match(None as Option<&User>, Some(&OffsetDateTime::now_utc())),
                Ok(())
            );

            assert_eq!(verify_if_none_match(None as Option<&User>, None), Ok(()));
        }

        #[test]
        fn ok_some_resource_created_after_accept_date() {
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: None,
                version: 1,
            };

            assert_eq!(
                verify_if_none_match(
                    Some(&resource),
                    Some(&resource.created.sub(Duration::from_millis(10)))
                ),
                Ok(())
            );

            assert_eq!(
                verify_if_none_match(Some(&resource), Some(&resource.created)),
                Ok(())
            );
        }

        #[test]
        fn error_some_resource_created_before_accept_date() {
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: None,
                version: 1,
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
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: None,
                version: 1,
            };

            assert_eq!(
                verify_if_none_match(Some(&resource), None),
                Err(IdempotencyError::PreconditionFailed)
            );
        }
    }

    mod test_if_match {
        use core::{
            ops::{Add, Sub},
            time::Duration,
        };

        use time::OffsetDateTime;

        use crate::{
            test::{Etag, User},
            verify_if_match, IdempotencyError, ResourceState,
        };

        #[test]
        fn ok_some_updated_resource_matching_etag() {
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: Some(OffsetDateTime::now_utc().add(Duration::from_millis(10))),
                version: 1,
            };

            assert_eq!(
                verify_if_match(Some(&resource), &resource.etag(), None),
                Ok(())
            );

            assert_eq!(
                verify_if_match(
                    Some(&resource),
                    &resource.etag(),
                    Some(&OffsetDateTime::now_utc())
                ),
                Ok(())
            );
        }

        #[test]
        fn ok_some_resource_not_updated_matching_etag() {
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: None,
                version: 1,
            };

            assert_eq!(
                verify_if_match(Some(&resource), &resource.etag(), None),
                Ok(())
            );

            assert_eq!(
                verify_if_match(
                    Some(&resource),
                    &resource.etag(),
                    Some(&OffsetDateTime::now_utc())
                ),
                Ok(())
            );
        }

        #[test]
        fn ok_some_resource_not_matching_etag_and_updated_after_accept_date() {
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: Some(OffsetDateTime::now_utc().add(Duration::from_millis(10))),
                version: 1,
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
                Ok(())
            );

            assert_eq!(
                verify_if_match(
                    Some(&resource),
                    &Etag::new(9, 2),
                    Some(&resource.updated.expect("Expect updated resource"))
                ),
                Ok(())
            );
        }

        #[test]
        fn error_some_resource_not_matching_etag_and_not_updated() {
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: None,
                version: 1,
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
            let resource = User {
                id: 1,
                created: OffsetDateTime::now_utc(),
                updated: Some(OffsetDateTime::now_utc().add(Duration::from_millis(10))),
                version: 1,
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
                    None as Option<&User>,
                    &Etag::new(1, 1),
                    Some(&OffsetDateTime::now_utc())
                ),
                Err(IdempotencyError::PreconditionFailed)
            );

            assert_eq!(
                verify_if_match(None as Option<&User>, &Etag::new(1, 1), None),
                Err(IdempotencyError::PreconditionFailed)
            );
        }
    }
}
