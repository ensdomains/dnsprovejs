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

`Oracle` interacts with DNSSEC Oracle smart contract.

.. autofunction:: Oracle#knownProof
.. autofunction:: Oracle#submitAll
.. autofunction:: Oracle#getAllProofs
.. autofunction:: Oracle#submitProof
.. autofunction:: Oracle#deleteProof
.. autofunction:: OracleProof

Proof
=====

`Proof` contains rrset and signature data which is submitted into DNSSEC Oracle.

.. autofunction:: Proof
.. autofunction:: Proof#toSubmit

DnsResult
===========

`DnsResult` is an object returned by calling `lookup` function and contains information about the DNS record.

.. autofunction:: DnsResult
