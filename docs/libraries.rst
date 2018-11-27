*******************
Libraries
*******************

DnsProver
==========

`DnsProver` allows you to lookup a domainname for a given DNS type and returns the DNS record and proofs which you can submit into DNSSEC Oracle. 

.. autofunction:: DnsProver#lookup
.. autofunction:: DnsProver#getOracle

Oracle
======

`Oracle` interact with DNSSEC Oracle smart contract.

.. autofunction:: Oracle#knownProof
.. autofunction:: Oracle#submitAll
.. autofunction:: Oracle#getAllProofs
.. autofunction:: Oracle#submitProof
.. autofunction:: Oracle#deleteProof
.. autofunction:: OracleProof
