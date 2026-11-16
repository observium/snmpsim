"""The answer to an SMI error, the same on both ways of answering."""
import pytest
from pysnmp.smi import error as smi_error

from snmpsim import responding

REQUEST = [
    ("1.3.6.1.2.1.1.5.0", None),
    ("1.3.6.1.2.1.1.7.0", None),
    ("1.3.6.1.2.1.1.6.0", None),
]


def test_an_error_about_a_variable_points_at_it():
    exc = smi_error.NoSuchNameError(idx=1)

    assert responding.error_response(exc, REQUEST) == ("noSuchName", 2, REQUEST)


def test_the_place_counts_the_variables_read_before_it():
    # the repetitions of a GETBULK are read after its non-repeaters
    exc = smi_error.BadValueError(idx=0)

    assert responding.error_response(exc, REQUEST, offset=2) == ("badValue", 3, REQUEST)


@pytest.mark.parametrize(
    "exc, error_index",
    [
        # no place named: pysnmp's answer, the first variable
        (smi_error.GenError(), 1),
        # a place past the request: pysnmp's answer as well, which turns an
        # index into 1 only where there are more variables than it counts,
        # and so sends this one as it is
        (smi_error.GenError(idx=5), 6),
    ],
)
def test_an_error_that_names_no_place_in_the_request_is_answered_as_pysnmp_does(
    exc, error_index
):
    status, index, var_binds = responding.error_response(exc, REQUEST)

    assert (status, index, var_binds) == ("genErr", error_index, REQUEST)


def test_too_big_comes_with_no_index_and_no_variables():
    exc = smi_error.TooBigError(idx=1)

    assert responding.error_response(exc, REQUEST) == ("tooBig", 0, [])


def test_an_error_pysnmp_has_no_status_for_is_a_general_error():
    class Unheard(smi_error.MibOperationError):
        pass

    assert responding.error_response(Unheard(idx=0), REQUEST)[:2] == ("genErr", 1)
