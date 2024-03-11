# MUSIC SIDECAR: Running multiple MUSICs as a Peer Group

## Problem Statement

While the "monolithic" multi-signer controller works, it does have an acceptance problem to overcome. The basic concern is that "signers" are unwilling to allow an external party (like MUSIC) access to modify zone content.

For this reason an alternative design, with multiple controllers, will be explored. Each controller will be located next to a signer and the signer will only communicate with that controller. The controller will then confer with the other controllers (the peers) to reach an agreement before each state transition is committed.

This is referred to as "MUSIC SIDECAR".

## Peer Communication

A peer need to communicate (as in request) each state transition that it believes should be executed. Likewise, it should be prepared to consider requests from other peers.

It is imperative that only one state transition is under discussion at any one time. Therefore some sort of distributed locking is likely needed.

## MUSIC Peer Protocol (outline, for discussion)

