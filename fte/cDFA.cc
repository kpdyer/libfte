#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <rank_unrank.h>

/*
 * This is a wrapper around rank_unrank.cc, to create the fte.cDFA
 * python module.
 * 
 * Updated for Python 3 compatibility with binary integer conversion.
 */


// Our custom DFAObject for holding and transporting a DFA*.
typedef struct {
    PyObject_HEAD
    DFA *obj;
} DFAObject;


// Our dealloc function for cleaning up when our fte.cDFA.DFA object is deleted.
static void
DFA_dealloc(DFAObject* self)
{
    if (self->obj != NULL) {
        delete self->obj;
        self->obj = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}


// Convert mpz_class to Python long using binary export (faster than string conversion)
static PyObject* mpz_to_pylong(const mpz_class& value) {
    if (value == 0) {
        return PyLong_FromLong(0);
    }
    
    // Get the number of bytes needed
    size_t count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
    
    // Export to bytes (big-endian)
    std::vector<unsigned char> buf(count);
    mpz_export(buf.data(), &count, 1, 1, 1, 0, value.get_mpz_t());
    
    // Use _PyLong_FromByteArray (big-endian, unsigned)
    return _PyLong_FromByteArray(buf.data(), count, 0, 0);
}


// Convert Python long to mpz_class using binary import (faster than string conversion)
static bool pylong_to_mpz(PyObject* pylong, mpz_class& result) {
    if (!PyLong_Check(pylong)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return false;
    }
    
    // Handle zero case
    int sign = _PyLong_Sign(pylong);
    if (sign == 0) {
        result = 0;
        return true;
    }
    
    if (sign < 0) {
        PyErr_SetString(PyExc_ValueError, "Expected a non-negative integer");
        return false;
    }
    
    // Get the number of bits, then bytes needed
    size_t nbits = _PyLong_NumBits(pylong);
    if (nbits == (size_t)-1 && PyErr_Occurred()) {
        return false;
    }
    size_t nbytes = (nbits + 7) / 8;
    
    // Export to bytes (big-endian)
    std::vector<unsigned char> buf(nbytes);
    if (_PyLong_AsByteArray((PyLongObject*)pylong, buf.data(), nbytes, 0, 0) < 0) {
        return false;
    }
    
    // Import into mpz
    mpz_import(result.get_mpz_t(), nbytes, 1, 1, 1, 0, buf.data());
    return true;
}


// The wrapper for calling DFA::rank.
// Takes a bytes object as input and returns an integer.
static PyObject * DFA__rank(PyObject *self, PyObject *args) {
    const char* word;
    Py_ssize_t len;

    if (!PyArg_ParseTuple(args, "y#", &word, &len))
        return NULL;

    // Copy our input word into a string.
    // We have to do the following, because we may have NUL-bytes in our strings.
    const std::string str_word = std::string(word, len);

    // Verify our environment is sane and perform ranking.
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "DFA object not initialized");
        return NULL;
    }

    mpz_class result;
    try {
        result = pDFAObject->obj->rank(str_word);
    } catch (std::exception& e) {
        PyErr_SetString(PyExc_RuntimeError, e.what());
        return NULL;
    }

    return mpz_to_pylong(result);
}


// Wrapper for DFA::unrank.
// On input of an integer, returns a bytes object.
static PyObject * DFA__unrank(PyObject *self, PyObject *args) {
    PyObject* c;

    if (!PyArg_ParseTuple(args, "O", &c))
        return NULL;

    // Convert Python int to mpz_class using binary conversion
    mpz_class to_unrank;
    if (!pylong_to_mpz(c, to_unrank)) {
        return NULL;
    }
    
    // Verify our environment is sane and perform unranking.
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "DFA object not initialized");
        return NULL;
    }

    std::string result;
    try {
        result = pDFAObject->obj->unrank(to_unrank);
    } catch (std::exception& e) {
        PyErr_SetString(PyExc_RuntimeError, e.what());
        return NULL;
    }

    // Format our std::string as a python bytes object and return it.
    PyObject* retval = PyBytes_FromStringAndSize(result.c_str(), result.length());

    return retval;
}


// Takes as input two integers [min, max].
// Returns the number of strings in our language that are at least
// length min and no longer than length max, inclusive.
static PyObject * DFA__getNumWordsInLanguage(PyObject *self, PyObject *args) {
    uint32_t min_val;
    uint32_t max_val;

    if (!PyArg_ParseTuple(args, "II", &min_val, &max_val))
        return NULL;

    // Verify our environment is sane, then call getNumWordsInLanguage.
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "DFA object not initialized");
        return NULL;
    }
    
    mpz_class num_words = pDFAObject->obj->getNumWordsInLanguage(min_val, max_val);

    return mpz_to_pylong(num_words);
}


// Boilerplate python object alloc.
static PyObject *
DFA_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    DFAObject *self;
    self = (DFAObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->obj = NULL;
    }
    return (PyObject *)self;
}


// Our initialization function for fte.cDFA.DFA
// On input of a [str, int], where str is a DFA specification,
// returns an fte.cDFA.DFA object that can perform ranking/unranking
// See rank_unrank.h for the significance of the input parameters.
static int
DFA_init(DFAObject *self, PyObject *args, PyObject *kwds)
{
    const char* dfa_str;
    Py_ssize_t dfa_len;
    unsigned int max_len;

    // Parse arguments: string and unsigned int
    if (!PyArg_ParseTuple(args, "s#I", &dfa_str, &dfa_len, &max_len)) {
        return -1;
    }

    // Try to initialize our DFA object.
    // An exception is thrown if the input AT&T FST is not formatted as we expect.
    // See DFA::_validate for a list of assumptions.
    try {
        const std::string str_dfa = std::string(dfa_str, dfa_len);
        DFA *dfa = new DFA(str_dfa, max_len);
        self->obj = dfa;
    } catch (std::exception& e) {
        PyErr_SetString(PyExc_RuntimeError, e.what());
        return -1;
    }

    return 0;
}


// Methods in fte.cDFA.DFA
static PyMethodDef DFA_methods[] = {
    {"rank",  DFA__rank, METH_VARARGS, "Rank a string to get its lexicographic index."},
    {"unrank",  DFA__unrank, METH_VARARGS, "Unrank an index to get the corresponding string."},
    {"getNumWordsInLanguage",  DFA__getNumWordsInLanguage, METH_VARARGS, 
     "Get the number of words in the language within a length range."},
    {NULL, NULL, 0, NULL}
};


// DFAType structure that contains the structure of the fte.cDFA.DFA type
static PyTypeObject DFAType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "cDFA.DFA",
    .tp_basicsize = sizeof(DFAObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor)DFA_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = PyDoc_STR("DFA object for ranking/unranking strings in a regular language"),
    .tp_methods = DFA_methods,
    .tp_init = (initproc)DFA_init,
    .tp_new = DFA_new,
};


// Module definition
static PyModuleDef cDFAmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "cDFA",
    .m_doc = "C extension module for DFA-based ranking and unranking.",
    .m_size = -1,
};


// Main entry point for the fte.cDFA module.
PyMODINIT_FUNC
PyInit_cDFA(void)
{
    if (PyType_Ready(&DFAType) < 0)
        return NULL;

    PyObject *m = PyModule_Create(&cDFAmodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&DFAType);
    if (PyModule_AddObject(m, "DFA", (PyObject *)&DFAType) < 0) {
        Py_DECREF(&DFAType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
