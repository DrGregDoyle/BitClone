# BitClone

## Learning Bitcoin by creating a Bitcoin clone

---

## Bitcoin Notes

Types of Bitcoin wallets:

- Full node: A program that validates the entire history of Bitcoin transactions. (A full node uses the most resources
  but offers full autonomy to the user.)
- Lightweight client (AKA: simplified-payment-verification (SPV) client): Connects to a full node for sending and
  receiving Bitcoin transacations, but stores the user wallet locally; partially validates the transactions it receives,
  and independently creates outgoing transactions.
- 3rd-party API client: One that interacts with Bitcoin through a 3rd-party system of APIs rather than by connecting to
  the Bitcoin network directly. The wallet may be stored by the user or 3rd-party servers. The client trusts the remote
  server to provide it with accurate information and protect its privacy.

NB: Bitcoin is a peer-to-peer (P2P) network. Full nodes are called the _peers_ and lightweight wallets (and other
software) are called _clients_.

- The pair of currencies given as (x/y) represent the market exchange rate for those currencies. e.g If (BTC/USD) =
  $62780, this means that 1 BTC can be exchanged for 62780 US dollars.

### Transactions

- Transactions are kept similar to double-entry bookkeeping. Each transaction contains one or more _inputs_ and one or
  more _outputs_. The _inputs_ represent spending funds and the _outputs_ represent receiving funds.
- The inputs and outputs will not necessarily add up to the same amount. The total amount represented by all the inputs
  should exceed the total amount assigned in the outputs. The difference between inputs and outputs represents the
  transaction fee, collected by the miner.
- The transaction also contains proof of ownership in the form of a digital signature (created using elliptic curves).
- The input in a transaction refers to an output of a previous transaction. It continues in this pattern until it
  reaches the original mining transaction which created the coins.
- In addition to one or more outputs that pay the receiver of bitcoins, many transactions will also include an output
  that pays the spender of the bitcoins, called a _change_ output. This is similar to the idea of paying $1 USD for
  something and getting $0.50 change. The input amount will likely not equal the amount to be paid to the recipient,
  hence the necessity of change output.
- However not every transaction has a change output. Such transactions are called _changeless_ transactions, and they
  can only have a single output.
- Different wallets use different strategies when choosing which inputs to use in a payment, called _coin selection_.

#### Types of transactions

- Simple payment (one input, two outputs - recipient and change)
- Aggregating transaction (collecting many small inputs to aggregate together to one output)
- Distributing transaction (AKA: payment batching) (one input to many outputs)

The wallet application contains all the logic necessary for creating a transaction. The user need only supply the
recipient address, amount and transaction fee. The wallet can create and sign this transaction without being connected
to the Bitcoin network. (However, to send the transaction the wallet will have to connect to the network.)

### UTXOs

A Bitcoin wallet that runs on a full node contains a copy of every confirmed transactions unspent outputs (that is,
outputs not yet referenced by an input of a later transaction). These are called _unspent transaction outputs (UTXOs)_.
Hence, a wallet that displays a users Bitcoin balance is in fact reporting the total amount assigned to all UTXOs with
the user's address.

### Propagation

Once the transaction is created, it needs to be propagated to the Bitcoin network. As every transaction contains all
necessary information to be processed, it does not matter how the user connects to the network. Once connected to the
Bitcoin network, the user (or an application) must send the transaction to a full node. Once received, a node will
validate the transaction and forward it to all other peers its connected to if the transaction is accepted. This method
of forwarding to all other connected peers is called _gossiping_. Thus the transaction will get propagated to a large
number of nodes in only a few seconds.

## Mining

Suppose a user has sent a transaction to the network and it is received by a node. The transaction does not become
accepted (part of the _blockchain_) until it is included in a _block_ through a process called _mining_. (Mining will be
explained in more depth later).

As a brief explanation, to mine a block means to calculate an appropriate value to include in the blocks header. This
calculation takes a lot of resources and is difficult to find. However verifying the solution takes a trivial amount of
computing. This solution type (hard to find, easy to validate) provides one of the benefits of Bitcoin.

Mining serves two purposes:

- Miners can only receive honest income from creating blocks that follow all of Bitcoin's _consensus rules_. Thus miners
  are incentivized to only include valid transactions in their blocks.
- Mining (currently) creates new Bitcoins in each block. The amount of Bitcoin created per block is limited (called the
  _mining reward_) and will vary over time. In fact, the mining reward will grow smaller over time according to a fixed
  schedule

A successful miner will collect the reward (in the form of new Bitcoins plus the transaction fees). However, the reward
will only be collected if the miner has only included valid transactions, with Bitcoin's _consensus_ rules determining
which transactions are valid. This provides security for Bitcoin without the need for a central authority.

Mining is designed to be a decentralized lottery. Each miner can create their own lottery ticket by creating a
_candidate block_ that includes the new transactions they want to include, plus some additional data fields. The
candidate block will then have its data _hashed_, and if the data meets the minimum requirements, the block is accepted.

### Hash function

A hash function is a type of mathematical function which, given the same input, will produce the same output each time.
But it is designed so that the output value is impossible to predict given the input value. In fact, given two input
values that are nearly identical, their hash values will be radically different.

Ex:

Suppose we have two strings: "bat" and "cat". Using the SHA-256 algorithm (a hashing function), we see the hash value
of 'bat' is

```
2b1af0fe3b9b32d6a425f0d4f9b06eade50cff70aaa41824da025576d00bbf47
```

but the hash value of 'cat' is

```
175cc6f362b2f75acd08a373e000144fdb8d14a833d4b70fd743f16a7039103f.
```

In this fashion, a hash value provides security as we cannot know ahead of time what the output of a hash function is
going to be. We emphasize that hash functions can take any value as input, but behind the scenes this input will get
translated into a numerical value. We see above that the output of a hash function is just an integer, given in
hexadecimal form.

### Proof of work

In order to mine a block, the hash value of a certain data field on the block must be less than a certain value, called
the _difficulty_ of the block. If a miner calculates the hash value of this data field and finds that its greater than
the difficulty, the miner will increase the value of a particular data field called the _nonce_, and retry the hash
function. In this fashion, the miner can continually try to find a new candidate hash value by increasing the nonce. The
speed at which a miner is able to calculate new hash values is called the miners _hash rate_.

Once an appropriate hash value has been found, the block is propagated across the network and other users can verify the
validity of the block by quickly performing the same hash function on the candidate. This makes the work necessary to
mine a valid block significant, but the verification of this block is trivial. The simple verification process is able
to probabalistically prove that work was done, so the data necessary to generate that proof (e.g., a valid block) is
called _proof of work (POW)_.

---

- UTXO
- Transaction
- Block
- Database
- Blockchain
- Mining
- Wallet
- Node
- API
- GUI