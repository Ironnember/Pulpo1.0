use pyo3::prelude::*;

mod ledger;
mod evidence;
mod merkle;
mod store;

#[pyfunction]
fn export_ledger_py(path: String) -> PyResult<String> {
    // Example wrapper — you can adjust this to your real logic
    let ledger_json = ledger::export_ledger_to_json(&path)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

    Ok(ledger_json)
}

#[pymodule]
fn pulpo_ledger_rust(py: Python, m: Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(export_ledger_py, py)?)?;
    Ok(())
}