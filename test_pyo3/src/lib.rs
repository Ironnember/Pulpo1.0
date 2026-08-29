use pyo3::prelude::*;

#[pyfunction]
fn hello() -> PyResult<String> {
    Ok("Hello from Rust!".into())
}

#[pymodule]
fn test_pyo3(py: Python, m: Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, py)?)?;
    Ok(())
}
