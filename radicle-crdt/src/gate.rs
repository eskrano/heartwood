use crate::Semilattice;

/// An optional value that once it is `closed`, it cannot be opened
/// again.
///
/// `open` elements are merged via the inner value's [`Semilattice`],
/// but `closed` gates will annihilate any open gates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gate<T>(Option<T>);

impl<T> Gate<T> {
    /// Create an open `Gate`, similar to [`Option::Some`].
    pub fn open(t: T) -> Self {
        Self(Some(t))
    }

    /// Create a closed `Gate`, similar to [`Option::None`].
    pub fn closed() -> Self {
        Self(None)
    }

    /// Maps a `Gate<T>` to `Gate<U>` by applying the function `f` to
    /// the contained value.
    pub fn map<U, F>(self, f: F) -> Gate<U>
    where
        F: FnOnce(T) -> U,
    {
        Gate(self.0.map(f))
    }

    /// Get the value of the `Gate`, returning `Some` if it is open
    /// and `None` if it is closed.
    pub fn get(&self) -> Option<&T> {
        self.0.as_ref()
    }

    /// Get the mutable reference of the value of the `Gate`,
    /// returning `Some` if it is open and `None` if it is closed.
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.0.as_mut()
    }

    /// Converts from `&Gate<T>` to `Gate<&T>`.
    pub fn as_ref(&self) -> Gate<&T> {
        Gate(self.0.as_ref())
    }

    /// Will return `true` if the gate is open.
    pub fn is_open(&self) -> bool {
        self.0.is_some()
    }

    /// Will return `true` if the gate is closed.
    pub fn is_closed(&self) -> bool {
        self.0.is_none()
    }

    /// Returns an iterator over the possibly contained value.
    pub fn iter(&self) -> Iter<'_, T> {
        Iter(self.0.iter())
    }

    /// Returns a mutable iterator over the possibly contained value.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        IterMut(self.0.iter_mut())
    }
}

impl<T> IntoIterator for Gate<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

pub struct Iter<'a, T>(std::option::Iter<'a, T>);

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<'a, T> DoubleEndedIterator for Iter<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

pub struct IterMut<'a, T>(std::option::IterMut<'a, T>);

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<'a, T> DoubleEndedIterator for IterMut<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

pub struct IntoIter<T>(std::option::IntoIter<T>);

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<T> DoubleEndedIterator for IntoIter<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

impl<T> From<T> for Gate<T> {
    fn from(t: T) -> Self {
        Self::open(t)
    }
}

impl<T> From<Option<T>> for Gate<T> {
    fn from(t: Option<T>) -> Self {
        Self(t)
    }
}

impl<T> From<Gate<T>> for Option<T> {
    fn from(Gate(t): Gate<T>) -> Self {
        t
    }
}

impl<T: Semilattice> Semilattice for Gate<T> {
    fn merge(&mut self, other: Self) {
        match (&mut self.0, other.0) {
            (Some(a), Some(b)) => {
                a.merge(b);
            }
            (None, Some(_)) => {}
            (Some(_), None) => {
                self.0 = None;
            }
            (None, None) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test;

    use super::Gate;

    use qcheck::Arbitrary;
    use qcheck_macros::quickcheck;

    impl<T: Arbitrary> Arbitrary for Gate<T> {
        fn arbitrary(g: &mut qcheck::Gen) -> Self {
            Self(Option::arbitrary(g))
        }
    }

    #[quickcheck]
    fn prop_gate_laws(a: Gate<bool>, b: Gate<bool>, c: Gate<bool>) {
        test::assert_laws(&a, &b, &c);
    }
}
