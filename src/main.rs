use avail_subxt::{api, build_client, primitives::Header};
use codec::{Compact, Decode, Encode};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sp_core::{
    blake2_128, blake2_256,
    crypto::Pair,
    ed25519::{self, Public, Signature},
    hashing::blake2_512,
    twox_128, Bytes, H256,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Deserialize, Debug)]
struct SubscriptionResponse {
    jsonrpc: String,
    result: String,
    id: i32,
}

#[derive(Deserialize, Debug)]
struct HeaderResponse {
    jsonrpc: String,
    result: Header,
    id: i32,
}

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

#[derive(Clone, Debug, Decode, Encode)]
pub struct Precommit {
    pub target_hash: H256,
    /// The target block's number
    pub target_number: u32,
}

#[derive(Clone, Debug, Decode)]
pub struct SignedPrecommit {
    pub precommit: Precommit,
    /// The signature on the message.
    pub signature: Signature,
    /// The Id of the signer.
    pub id: Public,
}
#[derive(Clone, Debug, Decode)]
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

#[derive(Debug, Decode)]
pub struct Authority(Public, u64);

#[derive(Deserialize, Debug)]
struct AuthorityResponse {
    jsonrpc: String,
    result: String,
    id: i32,
}

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

    //Subscribe to justifications
    let (a, b) = connect_async(url).await.unwrap();
    let (mut write, mut read) = a.split();
    let payload = format!(
        r#"{{"id": 1, "jsonrpc": "2.0", "method": "grandpa_subscribeJustifications", "params": []}}"#,
    );

    write.send(Message::Text(payload)).await.unwrap();

    let msg = read.next().await.unwrap().unwrap();

    let sub_resp: SubscriptionResponse =
        serde_json::from_slice(msg.into_data().as_slice()).unwrap();

    println!("Subscribe response: {sub_resp:?}");

    // receive stream of justifications

    while let Some(message) = read.next().await {
        // println!("msg:{:?}", message);
        let raw_just = message.unwrap().into_data();
        let resp: SubscriptionMessage = serde_json::from_slice(raw_just.as_slice()).unwrap();
        // println!("Grandpa Justifications: {resp:?}");
        // let j: GrandpaJustification = Decode::decode(&mut &raw_just[..]).unwrap();
        // println!("Just: {:?}", j);
        let raw = sp_core::bytes::from_hex(resp.params.result.as_str()).unwrap();
        let input = &mut &raw[..];
        let j: GrandpaJustification = Decode::decode(input).unwrap();
        assert!(input.len() == 0);
        println!("GRANDPA Justifications: {:?}", j);

        let request_header = format!(
            r#"{{"id": 2, "jsonrpc": "2.0", "method": "chain_getHeader", "params": ["{:?}"]}}"#,
            j.commit.target_hash
        );
        // println!("msg:{request_header}");
        write.send(Message::Text(request_header)).await.unwrap();
        let msg = read.next().await.unwrap().unwrap();
        // println!("Raw message: {msg:?}");

        let m: HeaderResponse = serde_json::from_slice(msg.into_data().as_slice()).unwrap();
        // println!("Header:{:?}", m.result);

        let header = m.result;
        let calculated_hash: H256 = Encode::using_encoded(&header, |e| blake2_256(e)).into();
        assert_eq!(j.commit.target_hash, calculated_hash);

        // Get current authorities set ID
        let key = format!(
            "0x{}{}",
            hex::encode(twox_128("Grandpa".as_bytes())),
            hex::encode(twox_128("CurrentSetId".as_bytes()))
        );
        // println!("key: {key}");
        let request_auths = format!(
            r#"{{"id": 3, "jsonrpc": "2.0", "method": "state_getStorage", "params": ["{key}"]}}"#,
        );
        write.send(Message::Text(request_auths)).await.unwrap();
        let msg = read.next().await.unwrap().unwrap();
        // println!("Raw message: {msg:?}");

        let resp: AuthorityResponse = serde_json::from_slice(msg.into_data().as_slice()).unwrap();
        // println!("resp:{}", resp.result);
        let resp_from_hex = sp_core::bytes::from_hex(resp.result.as_str()).unwrap();
        let set_id: u64 = Decode::decode(&mut resp_from_hex.as_slice()).unwrap();
        println!("SetId={set_id}");

        // Get authorities 2
        let key = format!(
            "0x{}{}",
            hex::encode(twox_128("AuthorityDiscovery".as_bytes())),
            hex::encode(twox_128("Keys".as_bytes()))
        );
        println!("key: {key}");
        let request_auths = format!(
            r#"{{"id": 3, "jsonrpc": "2.0", "method": "state_getStorage", "params": ["{key}"]}}"#,
        );
        write.send(Message::Text(request_auths)).await.unwrap();
        let msg = read.next().await.unwrap().unwrap();
        // println!("Raw message: {msg:?}");
        let resp: AuthorityResponse = serde_json::from_slice(msg.into_data().as_slice()).unwrap();
        let from_hex = sp_core::bytes::from_hex(resp.result.as_str()).unwrap();
        let input = &mut from_hex.as_slice();
        let auths: Vec<Public> = Decode::decode(input).unwrap();
        assert!(input.len() == 0);
        println!("Authority discovery: {auths:?}");

        // Get authorities 1
        let key = format!(
            "0x{}{}",
            hex::encode(twox_128("Babe".as_bytes())),
            hex::encode(twox_128("Authorities".as_bytes()))
        );
        println!("key: {key}");
        let request_auths = format!(
            r#"{{"id": 3, "jsonrpc": "2.0", "method": "state_getStorage", "params": ["{key}"]}}"#,
        );
        write.send(Message::Text(request_auths)).await.unwrap();
        let msg = read.next().await.unwrap().unwrap();
        // println!("Raw message: {msg:?}");
        let resp: AuthorityResponse = serde_json::from_slice(msg.into_data().as_slice()).unwrap();
        let from_hex = sp_core::bytes::from_hex(resp.result.as_str()).unwrap();
        let input = &mut from_hex.as_slice();
        let auths: Vec<Authority> = Decode::decode(input).unwrap();
        assert!(input.len() == 0);
        println!("Babe authorities:{auths:?}");

        // Get nextauthorities
        let key = format!(
            "0x{}{}",
            hex::encode(twox_128("Babe".as_bytes())),
            hex::encode(twox_128("NextAuthorities".as_bytes()))
        );
        println!("key: {key}");
        let request_auths = format!(
            r#"{{"id": 3, "jsonrpc": "2.0", "method": "state_getStorage", "params": ["{key}"]}}"#,
        );
        write.send(Message::Text(request_auths)).await.unwrap();
        let msg = read.next().await.unwrap().unwrap();
        // println!("Raw message: {msg:?}");
        let resp: AuthorityResponse = serde_json::from_slice(msg.into_data().as_slice()).unwrap();
        let from_hex = sp_core::bytes::from_hex(resp.result.as_str()).unwrap();
        let input = &mut from_hex.as_slice();
        let auths: Vec<Authority> = Decode::decode(input).unwrap();
        assert!(input.len() == 0);
        println!("Babe authorities:{auths:?}");

        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(j.commit.precommits[0].clone().precommit),
            &j.round,
            &set_id,
        ));
        // let p: ed25519::Public = auths[0].0;
        let p = j.commit.precommits[0].clone().id;
        let is_ok = <ed25519::Pair as Pair>::verify_weak(
            &j.commit.precommits[0].clone().signature.0[..],
            signed_message.as_slice(),
            p,
        );
        assert!(is_ok, "Not signed by this signature!");

        println!("#####")
    }
}
