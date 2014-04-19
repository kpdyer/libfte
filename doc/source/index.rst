Low-Level fteproxy API
**********************

The libfte module provides an implementation of Format-Transforming Encryption.
Given a regular expression R, key K, and message M, it's the job of an FTE primitive to return a ciphertext C in the language L(R).

Public-facing interfaces.

.. toctree::
   :maxdepth: 1

   encoder.rst

Supporting interfaces.

.. toctree::
   :maxdepth: 1

   automata.rst
   bit_ops.rst
   dfa.rst
   encrypter.rst
   rank_unrank.rst
