const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { Enigma, utils, eeConstants } = require('enigma-js/node');

var EnigmaContract;
if (typeof process.env.SGX_MODE === 'undefined' || (process.env.SGX_MODE != 'SW' && process.env.SGX_MODE != 'HW')) {
    console.log(`Error reading ".env" file, aborting....`);
    process.exit();
} else if (process.env.SGX_MODE == 'SW') {
    EnigmaContract = require('../build/enigma_contracts/EnigmaSimulation.json');
} else {
    EnigmaContract = require('../build/enigma_contracts/Enigma.json');
}
const EnigmaTokenContract = require('../build/enigma_contracts/EnigmaToken.json');


function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

let enigma = null;

contract("Secret_Account_addressbase", accounts => {
    let user1 = accounts[0];
    let user2 = accounts[1];
    let task;

    before(function() {
        enigma = new Enigma(
            web3,
            EnigmaContract.networks['4447'].address,
            EnigmaTokenContract.networks['4447'].address,
            'http://localhost:3333', {
                gas: 4712388,
                gasPrice: 100000000000,
                from: accounts[0],
            },
        );
        enigma.admin();
        enigma.setTaskKeyPair('cupcake');

        contractAddr = fs.readFileSync('test/secret_account_address.txt', 'utf-8');
    })

    // Helper function to wait for final task completion
    async function finalTaskStatus() {
        do {
            await sleep(1000);
            task = await enigma.getTaskRecordStatus(task);
        } while (task.ethStatus != eeConstants.ETH_STATUS_VERIFIED && task.ethStatus != eeConstants.ETH_STATUS_FAILED);

        return task.ethStatus;
    }

  // NOTE: helps with race-condition causing tests to fail
  beforeEach("sleep", async () => {
    await sleep(2000);
  });

  it("create address #1", async () => {

    const result1 = await compute({
      fn: "pub_register(Id, Pass, H160)",
      args: [
        [Namahage, "Id"],
        [Creo, "Pass"],
        [user1, "H160"],
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });

    expect(result1).to.equal(true);

    const result2 = await compute({
      fn: "pub_register(Id, Pass, H160)",
      args: [
        ['Namahage', "Id"],
        ['Creo', "Pass"],
        [user1, "H160"],
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });

    expect(result2).to.equal(false);
    
  it("Authoricate by pass", async () => {
    const result_pass = await compute({
      fn: "pub_authorize_by_pass(Id, Pass)",
      args: [
        ['Namahage', "Id"],
        ['Creo', "Pass"],
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });

    expect(result_pass).to.equal(true);

    const result_pass1 = await compute({
      fn: "pub_authorize_by_pass(Id, Pass)",
      args: [
        ['Namahage', "Id"],
        ['HAHAHA', "Pass"],
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });

    expect(result_pass1).to.equal(false);
  })
    const result_pass3 = await compute({
      fn: "pub_authorize_by_pass(Id, Pass)",
      args: [
        ['HAHAHA', "Id"],
        ['Creo', "Pass"],
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });

    expect(result_pass3).to.equal(false);


  const result_pass4 = await compute({
    fn: "pub_authorize_by_pass(Id, Pass)",
    args: [
      ['HAHAHA', "Id"],
      ['NANANA', "Pass"],
    ],
    userAddr: user1,
    contractAddr: secretContractAddr
  });

  expect(result_pass4).to.equal(false);
  
it("Authoricate by address", async () => {
  const result_addr1 = await compute({
  fn: "pub_authorize_by_pass(H160, Vec<u8>)",
    args: [
      [user1, "H160"],
      [vec1, "Vec<u8>"],
    ],
    userAddr: user1,
    contractAddr: secretContractAddr
  });
  expect(result_addr1).to.equal(true);

const result_addr2 = await compute({
    fn: "pub_authorize_by_pass(H160, Vec<u8>)",
      args: [
        [user1, "H160"],
        [vec2, "Vec<u8>"],
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });
    expect(result_addr2).to.equal(false);
  })

it("reset pass", async () => {
  const reset_pass1 = await compute({
    fn: "pub_reset_pass(Id, Pass, Pass)",
      args: [
        ['Namahage', "Id"],
        ['Creo', "Pass"],
        ['Nama', "Pass"]
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });
    expect(reset_pass1).to.equal(true);

  const reset_pass2 = await compute({
    fn: "pub_reset_pass(Id, Pass, Pass)",
      args: [
        ['Namahage', "Id"],
        ['Namah', "Pass"],
        ['Creo', "Pass"]
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });
    expect(reset_pass2).to.equal(false);
  })

it("reset address", async () => {
  const reset_addr1 = await compute({
    fn: "pub_reset_address(Id, Pass, H160)",
        args: [
          ['Namahage', "Id"],
          ['Nama', "Pass"],
          [user2, "H160"]
        ],
        userAddr: user1,
        contractAddr: secretContractAddr
      });
      expect(reset_addr1).to.equal(true);
  const reset_addr2 = await compute({
    fn: "pub_reset_address(Id, Pass, H160)",
      args: [
        ['Namahage', "Id"],
        ['Namah', "Pass"],
        [user2, "H160"]
      ],
      userAddr: user1,
      contractAddr: secretContractAddr
    });
  expect(reset_addr2).to.equal(false);
  });
it("reset pass by addr", async () => {
  const reset_pass_addr1 = await compute({
    fn: "pub_reset_pass_by_addr(H160, Id,  Pass, Vec<u8>)",
        args: [
          [user2, "H160"],
          ['Namahage', "Id"],
          ['Creo', "Pass"]
          [vec3, "Vec<u8>"]
        ],
        userAddr: user1,
        contractAddr: secretContractAddr
      });
    expect(reset_pass_addr1).to.equal(true);

  const reset_addr2 = await compute({
    fn: "pub_reset_pass_by_addr(H160, Id,  Pass, Vec<u8>)",
        args: [
          [user1, "H160"],
          ['Namahage', "Id"],
          ['Creo', "Pass"]
          [vec2, "Vec<u8>"]
        ],
        userAddr: user1,
        contractAddr: secretContractAddr
      });
  expect(reset_addr2).to.equal(false);
    });

  });

})
