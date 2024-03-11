# MUSIC SIDECAR

### Running multiple MUSICs as a Peer Group

## Problem Statement

While the "monolithic" multi-signer controller works, it does have an acceptance problem to overcome. The basic concern is that "signers" are unwilling to allow an external party (like MUSIC) access to modify zone content.

For this reason an alternative design, with multiple controllers, will be explored. Each controller will be located next to a signer and the signer will only communicate with that controller. The controller will then confer with the other controllers (the peers) to reach an agreement before each state transition is committed.

This is referred to as "MUSIC SIDECAR".

## Overview of multi-signer "processes"

In the current multi-signer internet-draft there are essentially 5 different processes defined. The first three deal with adding and removing "signers" from "signer groups". The next two deal with ZSK and KSK rollovers and the final process describe algorithm rollover.

In the current implementation of MUSIC, only the first three are really implmented. The reason is that it was discovered that signer initiated key rollovers caused significant problems in the multi-signer model because of the lag from the rollover (typically introduction of a new key) until MUSIC "noticed" the presence of the new key posed a potential window of vulnerability.

The document draft-ietf-dnsop-generalized-notify addresses this problem, but it not yet completely done and hence not implemented in mainstream nameservers.

## Peer Communication

A peer need to communicate (as in request) each state transition that it believes should be executed. Likewise, it should be prepared to consider requests from other peers.

It is imperative that only one state transition is under discussion at any one time. Therefore some sort of distributed locking is likely needed.

## MUSIC Peer Protocol (outline, for discussion)

In the SIDECAR system design each signer + local MUSIC instance constitute a pair working together. This pair is referred to as a "signer" below.

All protocol requests are sent from one signer to all other signers in the signer group. The number of signers is expected to be low and the frequency of communication also low, so having "everyone always know everything" is a reasonable choice.

It is important to note that, among other differences, the processes are essentially of two types: 

- state changes within a signer group where all signers are 
  known and in sync with the others
  
- state changes that affect the membership in a signer group

In MONOLITIC MODE (with a single MUSIC instance in control of all zones, signers and signer groups). In this case adding and removing signers from signer groups are a dynamic operation.

The assumption is that in SIDECAR MODE configuration of the other
signers in a signer group is a local and typically static configuration. Therefore, adding or removing a signer when using SIDECAR MODE will be an operation with several steps: first add the new signer in the configuration and then execute the "ADD-SIGNER" process (either preocess 1A or 1B). The reverse order when removing a signer ("REMOVE-SIGNER").

- When the process that is being executed is ADD-SIGNER then the 
  **requestor** should be the signer being added.

- When the process that is being executed is REMOVE-SIGNER then the 
  requestor must not be the departing signer, as that may result in 
  a deadlock (if the signer is being removed because it is no 
  longer functioning properly).

### REQUEST-TRANSITION <protocol, transition-id, zone, details>
	
	A signer issues a REQUEST-TRANSITION when something has 
	happened locally (either config change or signer change) that 
	requires the state transition.
	
### APPROVE-TRANSITION <protocol, transition-id, zone>

	A signer issues an APPROVE-TRANSITION when the requested 
	transition has been evaluated and verified not to conflict 
	with the FSM for the zone.
	
### EXECUTE-TRANSITION <protocol, transition-id, zone>

	The initiating signer issues an EXECUTE-TRANSITION after all 
	other signers in the signer group have sent an 
	APPROVE-TRANSITION.
	
### TRANSITION-DONE <protocol, transition-id, zone>

	Each signer confirms having executed the specified transition 
	in the state machine for the zone.

## Issues to Consider

1. In addition to rapid convergence to new shared state there is    
   also a concern about the risk for key id collisions between 
   signers (especially post the KeyTrap DNSSEC vulnerability was  
   disclosed early 2024).

     Therefore one part of the "approval proccess" will be to ensure
     that any new key being propsed by one signer doesn't share a 
     keyid with any other signer.
	 
