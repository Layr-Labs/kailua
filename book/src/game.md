# On-chain Sequencing Proposal
```admonish note
If you've successfully performed fast-track migration, you do not need to follow the steps on this page.
```

In this section you will be integrating the `KailuaGame` contract with your rollup's `DisputeGameFactory`.
This will allow Kailua sequencers to submit new proposals!

The commands below will be using Foundry's `cast` utility, which you should have installed as part of the
foundry [prerequisite](quickstart.md#prerequisites).

```admonish note
The below foundry commands expect both a parameter that determines the wallet to use and the rpc endpoint of the parent
chain.
You will have to add these two parameters manually to every command below.
For more information, refer to `cast call --help`, and `cast send --help`
```

```admonish tip
If your rollup `owner` account is controlled by a `Safe` contract, or some other multi-sig contract, you can use
`cast calldata` to get the necessary input that your wallet contract should forward.
```

## Set Collateral Requirement

Before allowing sequencing proposals past the anchor state, you'll need to set the bond value (in wei) required for sequencers.
This is done by calling the `setParticipationBond` function on the treasury contract using the `owner` wallet for your
rollup.

For example, if your bond value is 12 eth, first convert this to wei using `cast`:
```shell
cast to-wei 12
```
```
12000000000000000000
```
Then, configure the bond as follows using the rollup `owner` wallet:
```shell
cast send \
  [YOUR_DEPLOYED_TREASURY_CONTRACT] \
  "setParticipationBond(uint256 amount)" \
  12000000000000000000
```


## Set KailuaGame Implementation

The next step is to update the implementation for the Kailua game type stored in the `DisputeGameFactory` contract to
point towards the `KailuaGame` contract deployed previously.
This can be done as follows using your `owner` wallet:
```shell
cast send [YOUR_DISPUTE_GAME_FACTORY] \
  "setImplementation(uint32, address)" \
  [YOUR_KAILUA_GAME_TYPE] \
  [YOUR_DEPLOYED_GAME_CONTRACT]
```

```admonish success
You have now enabled Kailua sequencing proposals to be published!
```

## Designate Vanguard (Optional)
To assign a Vanguard, you'll need to call `assignVanguard` on the anchoring game instance you created.
This can be done as follows using your `owner` wallet:
```shell
cast send [YOUR_GAME_INSTANCE_ADDRESS] \
  "assignVanguard(address, uint64)" \
  [YOUR_VANGUARD_ADDRESS] \
  [YOUR_VANGUARD_ADVANTAGE]
```

```admonish success
You have now designated a Vanguard for Kailua sequencing proposals!
```

## Enable Withdrawals (Optional)

To enable your users to perform withdrawals using Kailua sequencing proposals, you will need to call 
`setRespectedGameType` on your `OptimismPortal2` contract using your `guardian` wallet.
```admonish bug
This action may cause your optimism `op-proposer` agent to crash.
However, you will later run the Kailua proposer agent for sequencing anyway.
```

```shell
cast send [YOUR_OPTIMISM_PORTAL] \
  "setRespectedGameType(uint32)" \
  [YOUR_KAILUA_GAME_TYPE]
```

```admonish success
You have now enabled withdrawals using resolved (finalized) Kailua sequencing proposals!
```
