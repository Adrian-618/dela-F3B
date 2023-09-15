# DEDIS Ledger Architecture for F3B

This is the revised dela for the paper: F3B: A Low-Overhead Blockchain Architecture with Per-Transaction Front-Running Protection.

Check the codes under dkg/pedersen for detailed implementations:
dkg/pedersen/mod.go implements the main functions of TDH2 and PVSS.

Currently, to test TDH2/PVSS performance, use the two scripts F3B.sh and PVSS.sh, and check the details in F3B_records_test.go and PVSS_records_test.go  

**Now the framework for TDH2 is used when running PVSS, to get the accurate performance, comment line 460-482, 606-620 in dkg/pedersen/hander.go, modify line 485 to fix err definition, and uncomment line 623;**

Check codes and comments for details.

