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