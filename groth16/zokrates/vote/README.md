(sort of) Anon Voting

An app is created that allows adding new members and voting on measures.

During membership initialization, member commits to a phrase they'll use when voting, this is stored on chain and the set of hashes is a public input to the snark.

> TODO: merkle-ize the hash set?

During voting, the snark ensures that the hash of the private passphrase matches one in the set and produces a proof that can be verified on chain.

> TODO: If merkle-ized, we should have the path computed in an out-of-snark process and the snark just verifies the path is valid

A logic sig is used to sign the app call transaction with proof/inputs as arguments, the lsig verifies the proof.

If this is a groth16 snark, and everyone needs to generate their own proof of a vote, how do we "share" the proving key? 
If everyone has their own proving key, how could it be anon since itd need to be verified against their personal vk?