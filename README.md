<p align="center">
  <img src="./imgs/the-city-rises.jpg" width="50%" height="50%" />
  <br/>
  Umberto Boccioni, <em>The City Rises</em>
</p>


# PlasmaBlind

PlasmaBlind is a private L2 protocol with instant client-side proving. Built upon [PlasmaFold](https://eprint.iacr.org/2025/1300), it leverages folding to keep proof generation costs low for both users and aggregators. PlasmaBlind adds sender-receiver unlinkability and confidential amounts through the [Nova](https://eprint.iacr.org/2021/370) folding scheme and its [BlindFold](https://eprint.iacr.org/2024/248) extension.

A technical note is available [here](paper/build/main.pdf).

PlasmaBlind operates in the UTXO model. Three roles interact:

1. Users prove transaction validity by folding their witness with a random pair (BlindFold), without running a full zkSNARK prover. This makes client-side proving *very* efficient (sub-100ms on a MacBook M1 Pro).
2. Aggregators collect user proofs and build blocks via two linked IVC chains: one accumulates user transaction validity proofs, the other executes L2 state transitions. This makes it possible to achieve the expressiveness of non-uniform PCD without its overhead. Our prototype aggregator reaches sub-300ms per-transaction aggregation on a desktop CPU (Intel i9-12900K).
3. The L1 rollup contract verifies a constant-size block validity proof.

In a similar vein to PlasmaFold, users maintain local balance proofs updated via IVC after each transaction to enable instant exits from the L2 without interacting with the aggregator.

PlasmaBlind leverages [Intmax2](https://eprint.iacr.org/2023/1082)'s data availability protocol to reach ~36,000 TPS theoretical throughput in a centralized setting. However, in contrast to Intmax2, users can skip blocks that contain no relevant transactions.

Note that PlasmaBlind can also operate with permissionless aggregators, reaching a theoretical ~1,800 TPS when broadcasting nullifiers on the Ethereum L1.

This repo provides an implementation of PlasmaBlind using the [`sonobe`](https://github.com/privacy-ethereum/sonobe) folding library and [`arkworks`](https://github.com/arkworks-rs). It is composed as follows:
```
core/        — shared data structures, circuits, and primitives
client/      — transaction validity proving (BlindFold) and balance proof IVC
aggregator/  — block building via dual IVC chains
```
