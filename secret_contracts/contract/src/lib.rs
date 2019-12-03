#![no_std]
extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate serde;
extern crate hex;
use enigma_crypto::{KeyPair, hash::Keccak256};
use eng_wasm::*;
use eng_wasm_derive::pub_interface;

/*
 Encrypted state keys 
*/
static USER_ID: &str = "ID_";

pub type Id = String;
pub type Pass = String;


#[derive(Serialize, Deserialize, std::fmt::Debug, Default)]
pub struct Account {
    id: Id,
    pass: pass,
    current_address: H160,
}

//A marker that shows whether authentication is passed
#[derive(Serialize, Deserialize, std::fmt::Debug)]
pub enum Authorize {
    ACCEPT,
    DENY,
}

// Public struct Contract which will consist of private and public-facing secret contract functions
pub struct Contract;

fn prepare_hash_multiple<B: AsRef<[u8]>>(messages: &[B]) -> Vec<u8> {
    // wasmi is using a 32 bit target as oppose to the actual machine that
    // is a 64 bit target. therefore using u64 and not usize
    let mut res = Vec::with_capacity(messages.len() * mem::size_of::<u64>());
    for msg in messages {
        let msg = msg.as_ref();
        let len = (msg.len() as u64).to_be_bytes();
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
    }
    res
}

/// verify if the address that is sending the tokens is the one who actually sent the transfer.
/// fix the function in "enigma-core/example/ERC20" to accept same message
/// メッセージと署名からpubkeyを導出する
/// this function can't define until enigmaMPC publishes function of authentication
fn verify(signer: H256, addr: H256, motions: String, sig: Vec<u8>) -> bool {
    let msg = [&addr.to_vec()[..], &motions.as_bytes()];
    let to_verify = Self::prepare_hash_multiple(&msg);
    let mut new_sig: [u8; 65] = [0u8; 65];
    new_sig.copy_from_slice(&sig[..65]);

    let accepted_pubkey = KeyPair::recover(&to_verify, new_sig).unwrap();
    *signer == *accepted_pubkey.keccak256()
}

// returns user id by "ID_USERID"
fn make_id_string(id: Id) -> String {
    let mut key = String::from(USER_ID);
    key.push_str(&id.to_string());
  
    return key;
  }
  
  // add prefix "0x" to address string
  fn make_address_string(address: H160) -> String {
    let addr_str: String = address.to_hex();
  
    return [String::from("0x"), addr_str].concat();
  }


// Private functions accessible only by the secret contract
impl Contract {
    //return new account if id and address is not used
    fn register(id:Id, pass: Pass, address: H160) -> Result<Account, &'static str> {
        if Self::is_exist(id) | Self::is_exist_address(address){
            return Err("id is already used");
        } else {
            let new_account = Account{
                id: id,
                pass: pass,
                current_address: address
            };
            return Some(new_account);
        }
    }

    //authorize by using id password(for login)
    fn authorize_by_pass( id: Id, pass: Pass) -> Authorize {
        if Self::get_pass_by_id(id) == Some(&pass) {
            return Authorize::ACCEPT;
        }
        return Authorize::DENY;
    }

    //authorize by using id address(for metamask)
    //third argument of verify function can be chosen by user in future
    fn authorize_by_address( address: H160, sig: Vec<u8>) -> Authorize {
        if verify(address, address, "Authentication by you".to_string(), sig) {
            return Authorize::ACCEPT;
        }
        return Authorize::DENY;
    }

    fn reset_pass(id:Id, pass: Pass, new_pass: Pass) -> Result<Account, Authorize> {
        match Self::authorize_by_pass(id, pass) {
            Authorize::ACCEPT => {
                let mut account = get_by_id(id);
                account.id = id;
                account.pass = pass;
                Some(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn reset_address(id: Id, pass: Pass, new_address: H160) -> Result<Account, Authorize> {
        match Self::authorize_by_pass(id, pass) {
            Authorize::ACCEPT => {
                let mut account = get_by_id(id);
                account.current_address = new_address;
                Some(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn reset_pass_by_addr(id: Id, pass: Pass, new_pass: H160, sig: Vec<u8>) -> Result<Account, Authorize> {
        match Self::authorize_by_address(id, sig) {
            Authorize::ACCEPT => {
                let mut account = get_by_id(id);
                account.id = id;
                account.pass = pass;
                Some(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn get_by_id (id: Id) -> Option<Account> {
        let id_string = &make_id_string(id);
        match read_state!(id_string){
            Some(account) => Some(account),
            None => None,
        }
    }

    fn is_exist(id: Id) -> bool {
        let id_string = &make_id_string(id);
        match read_state!(id_string) {
            Some(account) => true,
            None => false,
        }
    }

    fn is_exist_address(address: H160) -> bool {
        let address_string = &make_address_string(address);
        match read_state!(address_string) {
            Some(account) => true,
            None => false,
        }
    }

    fn resister_in_state(id: Id, address: H160, account: Account) -> (){
        let id_string = &make_id_string(id);
        let address_string = &make_address_string(address);
        write_state!(id_string => account);
        write_state!(address_string => id);
    }
}

// Public trait defining public-facing secret contract functions
#[pub_interface]
pub trait ContractInterface {
    fn registor(id: Id, pass: Pass) -> bool;
    // fn registor_without_pass(id: Id) -> Pass;
    fn authorize_by_pass(id: Id, pass: Pass) -> bool;
    fn authorize_by_address(address: H160, pass: Pass, sig: Vec<u8>) -> bool;
    fn pub_reset_pass(id:Id, pass: Pass, new_pass: Pass) -> bool;
    fn pub_reset_address(id: Id, pass: Pass, new_address: H160) -> bool;
    fn pub_reset_address_by_addr(id: Id, pass: Pass, new_address: H160) -> bool;
} 

// Implementation of the public-facing secret contract functions defined in the ContractInterface
// trait implementation for the Contract struct above
impl ContractInterface for Contract {
    #[no_mangle]
    fn pub_register(id: Id, pass: Pass, address: H160) -> bool{
        let new_account = Self::register(id, pass, address).unwrap_or_default();
        Self::resister_in_state(id, address, new_account); 
        return true
    }
    
    #[no_mangle]
    fn pub_authorize_pass(id: Id, pass: Pass) -> bool {
        match Self::authorize_by_pass(id, pass) {
            Authorize::ACCEPT => true,
            Authorize::DENY => false,
        }
    }

    #[no_mangle]
    fn pub_authorize_by_address(address: H160, pass: Pass, sig: Vec<u8>) -> bool {
        match Self::authorize_by_pass(id, pass, sig) {
            Authorize::ACCEPT => true,
            Authorize::DENY => false,
        }
    }

    #[no_mangle]
    fn pub_reset_pass(id:Id, pass: Pass, new_pass: Pass) -> bool {
        let new_account = Self::reset_pass(id, pass, new_pass).unwrap_or_default();
        Self::resister_in_state(id, address, new_account); 
        return true
    }

    #[no_mangle]
    fn pub_reset_address(id: Id, pass: Pass, new_address: H160) -> bool {
        let new_account = Self::reset_address(id, pass, new_address).unwrap_or_default();
        Self::resister_in_state(id, new_address, new_account); 
        return true
    }

    #[no_mangle]
    fn pub_reset_address_by_addr(id: Id, pass: Pass, new_address: H160) -> bool {
        let new_account = Self::reset_address_by_addr(id, pass, new_address).unwrap_or_default();
        Self::resister_in_state(id, new_address, new_account);
        return true
    }
}