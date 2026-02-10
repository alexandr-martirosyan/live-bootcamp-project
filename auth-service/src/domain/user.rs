use crate::domain::{Email, Password};

// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.
#[derive(Debug, Clone)]
pub struct User {
    email: Email,
    password: Password,
    requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa,
        }
    }

    pub fn email(&self) -> &Email {
        &self.email
    }

    pub fn password(&self) -> &Password {
        &self.password
    }

    pub fn requires_2fa(&self) -> bool {
        self.requires_2fa
    }
}
