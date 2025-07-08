use crate::core::authorization_request::RequestReference;

#[derive(Debug, Clone, Default)]
pub enum ByReference {
    #[default]
    False,
    True(RequestReference),
}
