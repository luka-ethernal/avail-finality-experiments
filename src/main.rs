use avail_subxt::{
    api::{self, runtime_types::sp_core::crypto::KeyTypeId},
    build_client,
    primitives::Header,
};
use codec::{Decode, Encode};
use futures_util::future::join_all;
use serde::de::Error;
use serde::Deserialize;
use sp_core::{
    blake2_256, bytes,
    ed25519::{self, Public as EdPublic, Signature},
    Pair, H256,
};
use subxt::rpc_params;
use tokio::sync::mpsc::unbounded_channel;

#[derive(Debug, Encode)]
pub enum SignerMessage {
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

#[derive(Clone, Debug, Decode, Encode, Deserialize)]
pub struct Precommit {
    pub target_hash: H256,
    /// The target block's number
    pub target_number: u32,
}

#[derive(Clone, Debug, Decode, Deserialize)]
pub struct SignedPrecommit {
    pub precommit: Precommit,
    /// The signature on the message.
    pub signature: Signature,
    /// The Id of the signer.
    pub id: EdPublic,
}
#[derive(Clone, Debug, Decode, Deserialize)]
pub struct Commit {
    pub target_hash: H256,
    /// The target block's number.
    pub target_number: u32,
    /// Precommits for target block or any block after it that justify this commit.
    pub precommits: Vec<SignedPrecommit>,
}

#[derive(Clone, Debug, Decode)]
pub struct GrandpaJustification {
    pub round: u64,
    pub commit: Commit,
    pub votes_ancestries: Vec<Header>,
}

impl<'de> Deserialize<'de> for GrandpaJustification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = bytes::deserialize(deserializer)?;
        Self::decode(&mut &encoded[..])
            .map_err(|codec_err| D::Error::custom(format!("Invalid decoding: {:?}", codec_err)))
    }
}

#[derive(Clone, Debug, Decode)]
pub enum Messages {
    Justification(GrandpaJustification),
    ValidatorSetChange((Vec<EdPublic>, u64)),
    UncheckedHeader(Header),
}

#[tokio::main]
async fn main() {
    let url = "ws://localhost:9944";
    let c = build_client(url, true).await.unwrap();
    let mut a = c.rpc().subscribe_finalized_block_headers().await.unwrap();

    // current set of authorities, implicitly trusted
    let validators_key = api::storage().session().validators();
    let mut validator_set: Vec<EdPublic> = c
        .storage()
        .at(None)
        .await
        .unwrap()
        .fetch(&validators_key)
        .await
        .unwrap()
        .unwrap()
        .iter()
        .map(|e| EdPublic::from_raw(e.0))
        .collect();

    let set_id_key = api::storage().grandpa().current_set_id();
    let mut set_id = c
        .storage()
        .at(None)
        .await
        .unwrap()
        .fetch(&set_id_key)
        .await
        .unwrap()
        .unwrap();

    println!(
        "Current set: {:?}",
        validator_set
            .iter()
            .map(|e| EdPublic::from_raw(e.0))
            .collect::<Vec<_>>()
    );

    let (msg_sender, mut msg_receiver) = unbounded_channel::<Messages>();

    // Produces headers and new validator sets
    tokio::spawn({
        let c = c.clone();
        let msg_sender = msg_sender.clone();
        async move {
            while let Some(Ok(header)) = a.next().await {
                let head_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
                msg_sender.send(Messages::UncheckedHeader(header)).unwrap();
                let events = c.events().at(Some(head_hash)).await.unwrap();

                let new_auths =
                    events.find_last::<avail_subxt::api::grandpa::events::NewAuthorities>();

                let set_id = c
                    .storage()
                    .at(Some(head_hash))
                    .await
                    .unwrap()
                    .fetch(&set_id_key)
                    .await
                    .unwrap()
                    .unwrap();
                if let Ok(Some(auths)) = new_auths {
                    let v: Vec<EdPublic> = auths
                        .authority_set
                        .into_iter()
                        .map(|(a, _)| EdPublic::from_raw(a.0 .0))
                        .collect();
                    println!("New set: {v:?}!");
                    msg_sender
                        .send(Messages::ValidatorSetChange((v, set_id)))
                        .unwrap();
                }
            }
        }
    });

    let j: Result<subxt::rpc::Subscription<GrandpaJustification>, subxt::Error> = c
        .rpc()
        .subscribe(
            "grandpa_subscribeJustifications",
            rpc_params![],
            "grandpa_unsubscribeJustifications",
        )
        .await;
    let mut j = j.unwrap();

    // Produces justifications
    tokio::spawn(async move {
        while let Some(Ok(just)) = j.next().await {
            msg_sender.send(Messages::Justification(just)).unwrap();
        }
    });

    let mut unchecked_headers: Vec<Header> = vec![];
    let mut justifications: Vec<GrandpaJustification> = vec![];
    // Gathers blocks, justifications and validator sets and checks finality
    loop {
        match msg_receiver.recv().await.unwrap() {
            Messages::Justification(justification) => {
                println!(
                    "New just on block: {}, hash: {:?}",
                    justification.commit.target_number, justification.commit.target_hash
                );
                justifications.push(justification);
            }
            Messages::ValidatorSetChange(valset) => {
                println!("New valset: {valset:?}");
                (validator_set, set_id) = valset;
            }
            Messages::UncheckedHeader(header) => {
                let hash: H256 = Encode::using_encoded(&header, blake2_256).into();
                println!("Header num={}, hash: {hash:?}", header.number);
                unchecked_headers.push(header);
            }
        }

        while let Some(h) = unchecked_headers.pop() {
            let hash = Encode::using_encoded(&h, blake2_256).into();

            if let Some(pos) = justifications
                .iter()
                .position(|e| e.commit.target_hash == hash)
            {
                let just = justifications.swap_remove(pos);
                // Form a message which is signed in the justification
                let signed_message = Encode::encode(&(
                    &SignerMessage::PrecommitMessage(just.commit.precommits[0].clone().precommit),
                    &just.round,
                    &set_id,
                ));

                // Verify all the signatures of the justification signs the hash of the block
                let sigs = just
                    .commit
                    .precommits
                    .iter()
                    .map(|precommit| async {
                        let is_ok = <ed25519::Pair as Pair>::verify_weak(
                            &precommit.clone().signature.0[..],
                            signed_message.as_slice(),
                            &precommit.clone().id,
                        );
                        assert!(is_ok, "Not signed by this signature!");
                        let id = precommit.clone().id.0;
                        let session_key_key_owner = api::storage()
                            .session()
                            .key_owner(KeyTypeId(sp_core::crypto::key_types::GRANDPA.0), id);
                        c.storage()
                            .at(Some(precommit.precommit.target_hash))
                            .await
                            .unwrap()
                            .fetch(&session_key_key_owner)
                            .await
                    })
                    .collect::<Vec<_>>();
                let sig_owners = join_all(sigs)
                    .await
                    .into_iter()
                    .map(|e| e.unwrap().unwrap())
                    .collect::<Vec<_>>();
                // Match all the signatures to the current validator set.
                let num = sig_owners.iter().fold(0usize, |acc, x| {
                    if validator_set.iter().find(|e| e.0.eq(&x.0)).is_some() {
                        acc + 1
                    } else {
                        acc
                    }
                });
                println!(
                    "Number of matching signatures: {num}/{}",
                    validator_set.len()
                )
            } else {
                eprintln!("No match!");
            }
        }
    }
}
