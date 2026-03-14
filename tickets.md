# BitClone ToDo list

## Formatting Tasks

- ~~Each Serializable class will have a table in the docstring containing:~~
    - ~~variable name~~
    - ~~data type in python~~
    - ~~serialized format~~
    - ~~serialized length~~

## Implementation Tasks

~~Serialized to_dict method~~

- ~~Have a flag for formatted vs plaintext~~
- ~~Default will be serialized formatted~~
- ~~The to_payload and to_dict methods will overlap.~~
- ~~Needs to be ordered in serialization order~~
- ~~Modify serializable - have to_dict method to produce the serialized format, and to_data to produce the raw data
  (for display)~~

- ~~Block Dict~~
    - ~~Add target as well as bits~~
- ~~Network~~
    - ~~Create BitIP class for handling ip addresses~~
    - ~~Needs to inherit from Serializable.~~
- Add the CheckLockTimeVerify opcode (redefine NOP2)
- Use the imported formatted class within each file, don't assign these to be file variables, this is unnecessary
  extra work
- ~~Straighten out the is_version bools with NetAddr and Addr and Version Messages~~
- Add all possible getrand functions to conftest for testing
- Separate scriptpubkey and scriptsig into separate files. Have ScriptType as enum for classification
- Change Transactions to Tx and network related transactions to Txn