use belenios::datatypes::election::ElectionBuilder;
use belenios::datatypes::questions::QuestionBuilder;
use belenios::participants::credential_authority::CredentialAuthority;
use belenios::participants::messages::*;
use belenios::participants::participant_template::*;
use belenios::participants::server_admin::ServerAdmin;
use belenios::participants::trustee::Trustee;
use belenios::participants::voter::Voter;
use belenios::participants::voting_server;
use belenios::participants::voting_server::VotingServer;
use ring::rand::SystemRandom;
use std::sync::{Arc, Mutex};

fn main() {
    //
    // ***START OF THE ELECTION SETUP PHASE***
    //

    // THE ELECTION SETUP
    let NUM_VOTERS = 10;
    let NUM_TRUSTEES = 9;
    // Defining the weights of the voters (10 voters of weight 1 each).
    let voters = vec![1; NUM_VOTERS];
    let election = E1MBuilder::default().voters(voters).build().unwrap();

    // Defining the various parties who participate in the election.
    let rng = Arc::new(Mutex::new(SystemRandom::new()));
    // Loading election into voting server and server administrator
    let server_admin = ServerAdmin::new(rng.clone());
    // Loading election into voting server
    let voting_server = VotingServer::new(rng.clone());

    let (server_admin, message_SA_to_CA) = server_admin.process_message(election.clone());
    let (voting_server, message_VS_to_CA) = voting_server.process_message(election);
    let message_to_CA = E3M::from((message_VS_to_CA, message_SA_to_CA));
    let credential_authority = CredentialAuthority::new(rng.clone());
    let (credential_authority, message_to_voters) =
        credential_authority.process_message(message_to_CA);

    let message_to_voters: Vec<E4Mi> = message_to_voters.into();
    let mut voters = Vec::new();
    // Setting up the voters
    for i in 0..NUM_VOTERS {
        let new_voter = Voter::new(rng.clone());
        let (new_voter, _) = new_voter.process_message(message_to_voters[i].clone());
        voters.push(new_voter);
    }
    // Credential Authority gives the public list of weights/stuff to the Voting Server.
    let (credential_authority, message) = credential_authority.process_message(EmptyMessage);
    let (voting_server, message) = voting_server.process_message(message);
    message
        .check
        .expect("The voting server failed the check in E7");
    // Voting Server initializes the Trustees
    let mut trustees = Vec::new();
    let mut trustee_keys = Vec::new();

    for i in 0..NUM_TRUSTEES {
        let new_trustee = Trustee::new(rng.clone());
        let (new_trustee, trustee_key) = new_trustee.process_message(EmptyMessage);
        trustees.push(new_trustee);
        trustee_keys.push(trustee_key);
    }
    let trustee_keys: E9M = trustee_keys.into();
    let (voting_server, message) = voting_server.process_message(trustee_keys);
    message.check.expect(
        "If a trustee tried to fake a ZK proof, their index has been recorded in this message",
    );
    //
    // DEFINING THE ELECTION
    //
    let quest = "Who should be IACR director in 2021?";
    let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];
    let question_one = QuestionBuilder::default()
        .question(quest)
        .answers(ans)
        .build()
        .unwrap();
    let quest = "Which Hardness Assumption will be broken next?";
    let ans = vec![
        "RLWE with Small Galois Group",
        "Small Moduli LWR",
        "RSA will be destroye",
    ];
    let question_two = QuestionBuilder::default()
        .question(quest)
        .answers(ans)
        .build()
        .unwrap();
    let version: usize = 1;
    let description = "This is a Test Election".to_string();
    let name = "Test Election".to_string();
    let admin_name = "Mark Schultz's Left Hand".to_string();
    let ca_name = "Mark Schultz's Right Hand".to_string();
    //
    // END DEFINING THE ELECTION
    //

    let message: E10M = E10MBuilder::default()
        .questions(vec![question_one, question_two])
        .version(1)
        .description(description)
        .name(name)
        .administrator(admin_name)
        .credential_authority(ca_name)
        .build()
        .unwrap();
    let (voting_server, election_message) = voting_server.process_message(message);
    // This message defines the election, transmit copies of it to voters eventually.
    let (credential_authority, message) =
        credential_authority.process_message(election_message.clone());
    message
        .check
        .expect("The Credential Authority and the Voting Server disagree over the public list L");
    //
    // *** END OF THE ELECTION SETUP PHASE ***
    //

    //
    // *** START OF THE VOTING PHASE ***
    //

    // Transmit the election to each voter.
    let voters: Vec<(Voter<belenios::participants::voter::V1>, EmptyMessage)> = voters
        .into_iter()
        .map(|v| v.process_message(election_message.clone()))
        .collect();
}
