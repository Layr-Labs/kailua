# Setup

Make sure to first install the [prerequisites](quickstart.md#prerequisites) from the quickstart
section before proceeding.

## Installation

Before you can start migrating your rollup, you'll need to build and install Kailua's binaries by calling the following
commands from the root project directory:

```admonish tip
Do not run these `install` commands in parallel.
Each binary installation will take time to reproducibly build the FPVM program in release mode.
If you install them in parallel, GitHub may throttle you, leading to a docker build error.
```

### CLI Binary
```shell
cargo install kailua-cli --path bin/cli --locked
```

### Prover Binary
```admonish info
At the cost of longer compilation time, you can embed the RISC Zero prover logic into `kailua-host` instead of having 
it utilize your locally installed RISC Zero `r0vm`.
To do this, add `-F prove` to the command below.
```

```shell
cargo install kailua-host --path bin/host --locked
```


## Configuration

Once your installation is successful, you should be able to run the following command to fetch the Kailua configuration
parameters for your rollup instance:

```shell
kailua-cli config --op-node-url [YOUR_OP_NODE_URL] --op-geth-url [YOUR_OP_GETH_URL] --eth-rpc-url [YOUR_ETH_RPC_URL]
```

Running the above command against the respective op-sepolia endpoints should produce the following output:
```
RISC0_VERSION: 1.2.3
FPVM_IMAGE_ID: 0xC20F44B56D72241F05E74E9C98B1B4812D7F367D639A52362EEB1F5D023E7821
FPVM_ELF_SIZE: 27266048
CONTROL_ROOT: 0x8CDAD9242664BE3112ABA377C5425A4DF735EB1C6966472B561D2855932C0469
CONTROL_ID: 0x04446E66D300EB7FB45C9726BB53C793DDA407A62E9601618BB43C5C14657AC0
SET_BUILDER_ID: 0x744CCA56CDE6933DEA72752C78B4A6CA894ED620E8AF6437AB05FAD53BCEC40A
RISC_ZERO_VERIFIER: 0x925D8331DDC0A1F0D96E68CF073DFE1D92B69187
GENESIS_TIMESTAMP: 1691802540
BLOCK_TIME: 2
ROLLUP_CONFIG_HASH: 0xADEA0C301681F81EA5CF9DD3A1A4BBE728E88CD540BDA4A5276809C87A9084CD
DISPUTE_GAME_FACTORY: 0x05F9613ADB30026FFD634F38E5C4DFD30A197FA1
OPTIMISM_PORTAL: 0x16FC5058F25648194471939DF75CF27A2FDC48BC
KAILUA_GAME_TYPE: 1337
```

```admonish warning
Make sure that your `FPVM_IMAGE_ID` matches the value above.
This value determines the exact program used to prove faults.
```

```admonish note
If your `RISC_ZERO_VERIFIER` value is blank, this means that your rollup might be deployed on a base layer that does
not have a deployed RISC Zero zkVM verifier contract.
This means you might have to deploy your own verifier.
Always revise the RISC Zero [documentation](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)
to double-check verifier availability.
```

Once you have these values you'll need to save them for later use during migration.

## Telemetry

All Kailua binaries and commands support exporting telemetry data to an
[OTLP Collector](https://opentelemetry.io/docs/collector/).
The collector endpoint can be specified using the `--otlp-collector` parameter, or through specifying the
`OTLP_COLLECTOR` environment variable.
