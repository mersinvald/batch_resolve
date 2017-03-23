macro_rules! cell {
    ($expr:expr) => (::std::cell::RefCell::new($expr))
}

macro_rules! uncell {
    ($expr:expr) => (*$expr.borrow())
}

macro_rules! uncell_mut {
    ($expr:expr) => (*$expr.borrow_mut())
}