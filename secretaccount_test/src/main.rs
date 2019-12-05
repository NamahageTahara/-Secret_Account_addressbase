#![no_std]
extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate serde;
extern crate hex;
extern crate enigma_crypto;
extern crate rustc_hex;
use enigma_crypto::{KeyPair, hash::Keccak256};
use serde::{Deserialize, Serialize};
use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use rustc_hex::ToHex;


/*
 Encrypted state keys 
*/
static USER_ID: &str = "ID_";

type Id = String;
type Pass = String;
type AccountInfo = (Id, Pass, H160);


#[derive(Serialize, Deserialize, Default)]
pub struct Account {
    id: Id,
    pass: Pass,
    current_address: H160,
}

//A marker that shows whether authentication is passed
#[derive(Serialize, Deserialize)]
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
fn verify(signer: H160, addr: H160, motions: String, sig: Vec<u8>) -> bool {
    let msg = [&addr.to_vec()[..], &motions.as_bytes()];
    let to_verify = prepare_hash_multiple(&msg);
    let mut new_sig: [u8; 65] = [0u8; 65];
    new_sig.copy_from_slice(&sig[..65]);

    let accepted_pubkey = KeyPair::recover(&to_verify, new_sig).unwrap();
    *signer == *accepted_pubkey.keccak256()
}

// returns user id by "ID_USERID"
fn make_id_string(id: &Id) -> String {
    let mut key = String::from(USER_ID);
    key.push_str(&id.to_string());
  
    return key;
  }
  
  // add prefix "0x" to address string
  fn make_address_string(address: &H160) -> String {
    let addr_str: String = address.to_hex();
  
    return [String::from("0x"), addr_str].concat();
  }


// Private functions accessible only by the secret contract

    //return new account if id and address is not used
    fn register(id: &Id, pass: &Pass, address: &H160) -> Result<Account, &'static str> {
        if true{
            return Err("id is already used");
        } else {
            let new_account = Account{
                id: id.to_string(),
                pass: pass.to_string(),
                current_address:  *address
            };
            return Ok(new_account);
        }
    }

    //authorize by using id password(for login)
    fn authorize_by_pass( id: &Id, pass: &Pass) -> Authorize {
        if &Self::get_by_id(id).unwrap_or_default().pass == pass {
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

    fn reset_pass(id: &Id, pass: &Pass, new_pass: &Pass) -> Result<Account, &'static str> {
        match Self::authorize_by_pass(id, pass) {
            Authorize::ACCEPT => {
                let mut account = Self::get_by_id(id).unwrap();
                account.id = id.to_string();
                account.pass = new_pass.to_string();
                Ok(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn reset_address(id: &Id, pass: &Pass, new_address: &H160) -> Result<Account, &'static str> {
        match Self::authorize_by_pass(id, pass) {
            Authorize::ACCEPT => {
                let mut account = Self::get_by_id(id).unwrap();
                account.current_address = *new_address;
                Ok(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn reset_pass_by_addr(address: H160, new_id: Id, new_pass: Pass, sig: Vec<u8>) -> Result<Account, &'static str> {
        match Self::authorize_by_address(address, sig) {
            Authorize::ACCEPT => {
                let mut account = Self::get_by_address(&address).unwrap();
                account.id = new_id.to_string();
                account.pass = new_pass.to_string();
                Ok(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn get_by_id (id: &Id) -> Option<Account> {
        let id_string = &make_id_string(id);
        match read_state!(id_string){
            Some(account) => Some(account),
            None => None,
        }
    }

    fn get_by_address (address: &H160) -> Option<Account> {
        let address_string = &make_address_string(address);
        match read_state!(address_string){
            Some(id) => {
                match Self::get_by_id(&id){
                    Some(account) => Some(account),
                    None => None,
                }
            },
            None => None,
        }
    }

    fn is_exist(id: &Id) -> bool {
        match Self::get_by_id(id) {
            Some(account) => true,
            None => false,
        }
    }

    fn is_exist_address(address: &H160) -> bool {
        match Self::get_by_address(address) {
            Some(account) => true,
            None => false,
        }
    }

    fn register_in_state(account: Account) -> (){
        let id = account.id.to_string();
        let id_string = &make_id_string(&account.id);
        let address_string = &make_address_string(&account.current_address);
        write_state!(id_string => account);
        write_state!(address_string => id);
    }

    fn show_data(id: &Id, pass: &Pass) -> Option<AccountInfo> {
        match Self::authorize_by_pass(id, pass) {
            Authorize::ACCEPT => {
                let account = &Self::get_by_id(id).unwrap();
                Some((account.id.to_string(), account.pass.to_string(), account.current_address))
            },
            Authorize::DENY => None
        }
    }


#[cfg(test)]
    mod tests {
        use super::*;
        use eng_wasm::Vec;
    #[test]
    fn test_resister(){
        let id = "Namahage";
        let pass = "Creo";
        let address: H160 = "0x9592b4af3004625D1Bfb8F6B2620554C6713Cdd8";
        let account = Account{
            id,
            pass,
            address,
        }
        assert_eq!(register(id, pass, address, true), Ok(account,"Cant register");
        assert!(a.registor(id, pass).is_err());
    }
    }
    }