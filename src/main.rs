use std::borrow::Borrow;
use std::ops::Deref;

use avail_subxt::api::runtime_types::sp_core::crypto::KeyTypeId;
use avail_subxt::api::runtime_types::sp_core::sr25519::Public as SrPublic;
use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use futures_util::StreamExt;
use serde::de::Error;
use serde::Deserialize;
use sp_core::crypto::key_types;
use sp_core::{
    blake2_256, bytes,
    crypto::Pair,
    ed25519::{self, Public as EdPublic, Signature},
    H256,
};
use subxt::rpc::RpcParams;

#[derive(Deserialize, Debug)]
pub struct SubscriptionMessageResult {
    pub result: String,
    pub subscription: String,
}

#[derive(Deserialize, Debug)]
pub struct SubscriptionMessage {
    pub jsonrpc: String,
    pub params: SubscriptionMessageResult,
    pub method: String,
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

#[derive(Debug, Decode)]
pub struct Authority(EdPublic, u64);

#[derive(Debug, Encode)]
pub enum SignerMessage {
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

#[tokio::main]
pub async fn main() {
    let url = "ws://localhost:9944";

    let c = build_client(url).await.unwrap();
    let mut e = c.events().subscribe().await.unwrap().filter_events::<(
        api::grandpa::events::NewAuthorities,
        api::grandpa::events::Paused,
        api::grandpa::events::Resumed,
    )>();

    tokio::spawn(async move {
        while let Some(ev) = e.next().await {
            let event_details = ev.unwrap();
            match event_details.event {
                (Some(new_auths), None, None) => println!("New auths: {new_auths:?}"),
                (None, Some(paused), None) => println!("Auth set paused: {paused:?}"),
                (None, None, Some(resumed)) => println!("Auth set resumed: {resumed:?}"),
                _ => unreachable!(),
            }
        }
    });

    let t = c.rpc().deref();
    let sub: Result<subxt::rpc::Subscription<GrandpaJustification>, subxt::Error> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;

    let mut sub = sub.unwrap();

    // Wait for new justification
    while let Some(Ok(justification)) = sub.next().await {
        println!("Justification: {justification:?}");

        // get the header corresponding to the new justification
        let header = c
            .rpc()
            .header(Some(justification.commit.target_hash))
            .await
            .unwrap()
            .unwrap();
        // a bit redundant, but just to make sure the hash is correct
        let calculated_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
        assert_eq!(justification.commit.target_hash, calculated_hash);
        // get current authority set ID
        let set_id_key = api::storage().grandpa().current_set_id();
        let set_id = c.storage().fetch(&set_id_key, None).await.unwrap().unwrap();
        println!("Current set id: {set_id:?}");

        // Form a message which is signed in the justification
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &set_id,
        ));
        // Extract the public key of the signed message
        let p: EdPublic = justification.commit.precommits[0].clone().id;

        // Verify signature
        let is_ok = <ed25519::Pair as Pair>::verify_weak(
            &justification.commit.precommits[0].clone().signature.0[..],
            signed_message.as_slice(),
            p,
        );
        assert!(is_ok, "Not signed by this signature!");
        println!("Justification AccountId: {p:?}");

        // Get the current authority set
        let authority_set_key = api::storage().authority_discovery().keys();
        let authority_set = c
            .storage()
            .fetch(&authority_set_key, None)
            .await
            .unwrap()
            .unwrap();
        let a: Vec<SrPublic> = authority_set.0.into_iter().map(|e| e.0).collect();
        println!("Current authority set: {a:?}");
        // Authority set is sr25519 key, justification is ed25519.
        let session_key_key_owner = api::storage()
            .session()
            .key_owner(KeyTypeId(sp_core::crypto::key_types::GRANDPA.0), p.0);
        let key_owner_p = c
            .storage()
            .fetch(&session_key_key_owner, None)
            .await
            .unwrap()
            .unwrap();
        println!("Owner p: {key_owner_p:?}");
        let session_key_key_owner = api::storage().session().key_owner(
            KeyTypeId(sp_core::crypto::key_types::AUTHORITY_DISCOVERY.0),
            a[0].0,
        );
        let key_owner_a = c
            .storage()
            .fetch(&session_key_key_owner, None)
            .await
            .unwrap()
            .unwrap();
        println!("Owner a: {key_owner_a:?}");

        assert_eq!(key_owner_a, key_owner_p, "Validator doesn't match");
    }
}
