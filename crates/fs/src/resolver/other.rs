// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Where there is no resolver yet (Windows until phase 3): no root opens,
//! so no [`Dir`] or [`Entries`] exists.

use std::convert::Infallible;
use std::fs::File;
use std::path::Path;

use super::{Create, Entry, OpenError, ResolveError};
use crate::name::{IndexPath, Name, NamePolicy};

/// A folder's root; none opens on this platform.
#[derive(Debug)]
pub struct Root(Infallible);

impl Root {
    /// Always [`OpenError::Unsupported`] on this platform.
    ///
    /// # Errors
    /// [`OpenError::Unsupported`].
    pub fn open(_path: &Path, _policy: NamePolicy) -> Result<Self, OpenError> {
        Err(OpenError::Unsupported)
    }

    /// The policy this root judges paths by.
    #[must_use]
    pub const fn policy(&self) -> NamePolicy {
        match self.0 {}
    }

    /// The hidden directory.
    ///
    /// # Errors
    /// None: no root exists here.
    pub fn hidden_dir(&self) -> Result<Dir, ResolveError> {
        match self.0 {}
    }

    /// The directory that holds `path`'s last component.
    ///
    /// # Errors
    /// None: no root exists here.
    pub fn parent(&self, _path: &IndexPath, _create: Create) -> Result<(Dir, Name), ResolveError> {
        match self.0 {}
    }
}

/// A directory beneath a folder's root; none exists on this platform.
#[derive(Debug)]
pub struct Dir(Infallible);

impl Dir {
    /// What is at `name`.
    ///
    /// # Errors
    /// None: no directory exists here.
    pub fn stat(&self, _name: &Name) -> Result<Option<Entry>, ResolveError> {
        match self.0 {}
    }

    /// Opens the file at `name`.
    ///
    /// # Errors
    /// None: no directory exists here.
    pub fn open_file(&self, _name: &Name, _expect: &Entry) -> Result<File, ResolveError> {
        match self.0 {}
    }

    /// The names in this directory.
    ///
    /// # Errors
    /// None: no directory exists here.
    pub fn entries(&self) -> Result<Entries, ResolveError> {
        match self.0 {}
    }
}

/// The names in a directory; none exists on this platform.
#[derive(Debug)]
pub struct Entries(Infallible);

impl Iterator for Entries {
    type Item = Result<Vec<u8>, ResolveError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_root_opens_here() {
        let got = Root::open(Path::new("."), NamePolicy::native());
        assert!(matches!(got, Err(OpenError::Unsupported)));
    }
}
