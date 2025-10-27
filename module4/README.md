# Module 4 - Smart Contract Security

## Overview

This module teaches students to identify and fix security vulnerabilities in smart contracts based on a professional audit report.

**Estimated duration**: 4-6 hours  
**Level**: Intermediate-Advanced  
**Prerequisites**: Module 3 completed (Testing)

## Learning Objectives

By the end of this module, students will be able to:

1. Read and interpret a security audit report
2. Identify reentrancy vulnerabilities
3. Identify data validation issues
4. Identify access control problems
5. Apply the Checks-Effects-Interactions pattern
6. Implement robust input validation
7. Implement function access control
8. Verify fixes through automated tests

## Structure

```
module4/
├── one-mil-nft-pixels--security-assessment-report--v1.1.pdf  # Audit report
├── contracts/
│   ├── OneMilNftPixels.sol                                   # VULNERABLE contract
│   ├── LunaToken.sol                                          # ERC20 token for payments
│   ├── MeowToken.sol                                          # Additional token
│   ├── PurrToken.sol                                          # Additional token
│   └── security-audit/
│       ├── Exploit-OMP001.sol                                 # Reentrancy exploit
│       ├── Exploit-OMP003.sol                                 # Frontrunning exploit
│       └── FIXED_CONTRACT/
│           └── OneMilNftPixels[FIXED].sol                     # Fixed version example
└── test/
    ├── Exploit-OMP001.js                                      # Reentrancy tests
    ├── Exploit-OMP002.js                                      # Validation tests
    ├── Exploit-OMP003.js                                      # Access control tests
    ├── OneMilNftPixels-deploy.js                              # Deployment tests
    ├── OneMilNftPixels-buy-success.js                         # Buy functionality tests
    ├── OneMilNftPixels-buy-fail.js
    ├── OneMilNftPixels-rebuy-success.js                       # Rebuy functionality tests
    ├── OneMilNftPixels-rebuy-fail.js
    ├── OneMilNftPixels-compensation.js                        # Compensation tests
    ├── OneMilNftPixels-admin-owner-success.js                 # Admin functions tests
    ├── OneMilNftPixels-admin-non-owner-fail.js
    ├── OneMilNftPixels-update-owner-success.js                # Update functionality tests
    ├── OneMilNftPixels-update-owner-fail.js
    └── OneMilNftPixels-update-non-owner-fail.js
```

## What to do?

1. Read the audit report (`one-mil-nft-pixels--security-assessment-report--v1.1.pdf`)
2. Identify the vulnerabilities in the vulnerable contract (`contracts/OneMilNftPixels.sol`)
3. Fix the vulnerabilities in the vulnerable contract (`contracts/OneMilNftPixels.sol`)
4. Run the tests to verify the fixes (`Exploit-OMP001.js`, `Exploit-OMP002.js`, `Exploit-OMP003.js`)
5. Submit the fixes (`OneMilNftPixels.sol`)

## Included Vulnerabilities

### OMP-001: Reentrancy in withdrawCompensation
**Severity**: CRITICAL  
**Type**: Reentrancy Attack  
**Concept**: Checks-Effects-Interactions Pattern

**Problem**: 
```solidity
// VULNERABLE - State updated AFTER external call
bool withdrawalSuccess = acceptedToken.transferAndCall(address(to), compensationBalance);
require(withdrawalSuccess, 'withdraw failed');
compensationBalances[_msgSender()] = 0;  // Too late
```

**Expected solution**:
```solidity
// SECURE - State updated BEFORE external call
compensationBalances[_msgSender()] = 0;  // First
bool withdrawalSuccess = acceptedToken.transferAndCall(address(to), compensationBalance);
require(withdrawalSuccess, 'withdraw failed');
```

**Key learning**: Always update state before external calls.


### OMP-002: NFTs can be purchased for free
**Severity**: CRITICAL  
**Type**: Data Validation  
**Concept**: Input Validation

**Problem**:
```solidity
// VULNERABLE - Doesn't validate data amount matches transferred amount
function _transferReceived(address _sender, uint256 _amount, bytes memory _data) private {
    (bytes4 selector, address newOwner, uint24 pixelId, bytes3 colour, uint256 amount) = 
        abi.decode(_data, (bytes4, address, uint24, bytes3, uint256));
    // Doesn't verify amount == _amount
    bytes memory callData = abi.encodeWithSelector(selector, newOwner, pixelId, colour, amount);
    (bool success, ) = address(this).delegatecall(callData);
}
```

**Expected solution**:
```solidity
// SECURE - Validates amounts match
function _transferReceived(address _sender, uint256 _amount, bytes memory _data) private {
    (bytes4 selector, address newOwner, uint24 pixelId, bytes3 colour, uint256 amount) = 
        abi.decode(_data, (bytes4, address, uint24, bytes3, uint256));
    
    require(amount == _amount, 'Amount mismatch');  // Critical validation
    // ... rest of code
}
```

**Key learning**: Always validate that calldata matches actual values.


### OMP-003: Frontrunners can deny NFT purchases
**Severity**: HIGH  
**Type**: Access Control  
**Concept**: Function Whitelisting

**Problem**:
```solidity
// VULNERABLE - Allows delegatecall of ANY function
function _transferReceived(address _sender, uint256 _amount, bytes memory _data) private {
    (bytes4 selector, ...) = abi.decode(_data, (bytes4, address, uint24, bytes3, uint256));
    bytes memory callData = abi.encodeWithSelector(selector, ...);
    (bool success, ) = address(this).delegatecall(callData);  // Dangerous
}
```

**Expected solution**:
```solidity
// SECURE - Only allows specific functions
function _transferReceived(address _sender, uint256 _amount, bytes memory _data) private {
    (bytes4 selector, ...) = abi.decode(_data, (bytes4, address, uint24, bytes3, uint256));
    
    // Whitelist of allowed functions
    require(
        selector == this.buy.selector || selector == this.update.selector,
        'Call of an unknown function'
    );
    
    // Direct call instead of delegatecall
    if (selector == this.buy.selector) {
        buy(_sender, pixelId, colour, amount);
    } else if (selector == this.update.selector) {
        update(_sender, pixelId, colour, amount);
    }
}
```

**Key learning**: Use whitelists and avoid delegatecall with unvalidated external data.


## Evaluation Criteria

### Tests that should pass (13 total)

**Exploit-OMP001.js** (5 tests):
- Transfer some lunas to exploit
- Transfer some lunas to oneMlnPix
- Should NOT exploit reentrancy in withdrawCompensation()
- Should NOT withdraw (almost) all Lunas from oneMlnPix
- Exploit balance should NOT increase

**Exploit-OMP002.js** (3 tests):
- Attacker should have 1 Luna token
- Attacker is NOT able to buy pixel for low price
- Pixel should remain unowned after exploit attempt

**Exploit-OMP003.js** (5 tests):
- Deployer buys pixel 1001
- Buyer becomes the new owner
- Deployer buys the pixel back
- Buyer receives a compensation
- Attacker should NOT call withdrawCompensation through transferAndCall

### Additional criteria

1. **Clean code**: Clear comments explaining fixes
2. **Don't break functionality**: All tests from previous module still pass
3. **Understanding**: Able to explain each vulnerability and its fix


## 🔍 Discussion Points

### Questions for students

1. **Why is the order of operations important in withdrawCompensation?**
   - Answer: To prevent reentrancy attacks

2. **What other contracts are vulnerable to reentrancy?**
   - Answer: Any that update state after external calls

3. **Why can't we trust calldata?**
   - Answer: It's controlled by the user and can be manipulated

4. **What's better: whitelist or blacklist?**
   - Answer: Whitelist is more secure (fail-secure)

5. **When is delegatecall safe?**
   - Answer: Only with trusted and validated code


## 🐛 Common Problems

### Problem 1: Tests don't compile
**Cause**: Incorrect ethers.js version  
**Solution**: Verify using ethers.js v6

### Problem 2: "Amount mismatch" in normal tests
**Cause**: Validation too strict  
**Solution**: Only validate in _transferReceived, not in buy/update

### Problem 3: Gas too high
**Cause**: Redundant calls  
**Solution**: Optimize execution flow

### Problem 4: Old tests fail
**Cause**: Changed contract behavior  
**Solution**: Verify only necessary changes were made


## 📚 Additional Resources

### For students
- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security Patterns](https://docs.openzeppelin.com/contracts/4.x/)
- [SWC Registry](https://swcregistry.io/)


## Submission Checklist

Students should submit:

- [ ] Modified contract code (`OneMilNftPixels.sol`)
- [ ] All tests passing (screenshot or logs)
- [ ] Document explaining:
  - [ ] Each identified vulnerability
  - [ ] Implemented fix
  - [ ] Why the fix is effective
- [ ] Git repository with descriptive commits


## Support

If students have questions:

1. **Technical**: Refer them to README and report
2. **Conceptual**: Discuss in Q&A session
3. **Implementation**: Give hints without revealing complete solution

**Allowed hints**:
- "Look for where state is updated and where external call is made"
- "What parameters does _transferReceived receive?"
- "How can you verify which function is being called?"

**NOT allowed hints**:
- Give exact solution code
- Modify tests to make them pass
- Do the work for them

---

**Next Steps**: After completing this module, students will have a better understanding of smart contract security and be ready to apply these skills to real-world projects.
