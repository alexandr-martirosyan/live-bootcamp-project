#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub email: String,
    pub password: String,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: &str, password: &str, requires_2fa: bool) -> Self {
        Self {
            email: email.to_owned(),
            password: password.to_owned(),
            requires_2fa,
        }
    }
}
