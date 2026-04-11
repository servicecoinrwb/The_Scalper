// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ═══════════════════════════════════════════════════════════════════════════════
//  BlazeTradingFund — Patched v2
//
//  Security fixes applied:
//  [1] ReentrancyGuard — inline, no external dependency
//  [2] SafeERC20 — low-level call wrapper validates USDT return value
//  [3] Checks-Effects-Interactions (CEI) — state zeroed before ALL external calls
//  [4] Front-run fix — shares snapshotted BEFORE funds leave in withdrawFundsToTrading
//  [5] Phase guard on depositReturnsUSDT
//  [6] Zero-address validation on constructor + setTrader
//  [7] Separate ETH/USDT share pools — no cross-decimal arithmetic
//  [8] Emergency pause + owner emergency-withdraw for stuck phases
//  [9] Overflow — Solidity 0.8.x built-in; share math uses mulDiv helper
// ═══════════════════════════════════════════════════════════════════════════════

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract BlazeTradingFund {

    // ─── Roles ────────────────────────────────────────────────────────────────
    address public owner;
    address public trader;

    // USDT on Ethereum mainnet (6 decimals)
    IERC20 public constant USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);

    // ─── FIX [1]: Inline ReentrancyGuard ─────────────────────────────────────
    uint256 private _reentrancyStatus;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED     = 2;

    modifier nonReentrant() {
        require(_reentrancyStatus != _ENTERED, "Reentrant call");
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    // ─── FIX [8]: Emergency pause ─────────────────────────────────────────────
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    // ─── Whitelist ────────────────────────────────────────────────────────────
    mapping(address => bool) public whitelist;
    address[] private _depositorList;
    mapping(address => bool) private _isDepositor;

    // ─── Deposit Tracking ────────────────────────────────────────────────────
    // FIX [7]: ETH and USDT are tracked in entirely separate pools.
    //          No cross-decimal arithmetic ever occurs.
    mapping(address => uint256) public ethDeposited;   // wei (18 dec)
    mapping(address => uint256) public usdtDeposited;  // raw (6 dec)
    uint256 public totalEthDeposited;
    uint256 public totalUsdtDeposited;

    // ─── Cycle State ──────────────────────────────────────────────────────────
    enum Phase { OPEN, TRADING, RETURNING }
    Phase public phase;

    // FIX [7]: Shares stored as numerator over SHARE_DENOM — separately per asset.
    //          Using 1e12 denominator (12-digit precision) to avoid precision loss
    //          even with very small or very large deposits.
    uint256 private constant SHARE_DENOM = 1e12;

    mapping(address => uint256) public ethShareOf;   // * SHARE_DENOM => fraction of ETH pool
    mapping(address => uint256) public usdtShareOf;  // * SHARE_DENOM => fraction of USDT pool

    // Snapshot totals taken at snapshot time (may differ from pool if tokens arrive later)
    uint256 private _snapshotEth;
    uint256 private _snapshotUsdt;

    // ─── Revenue Tracking ─────────────────────────────────────────────────────
    struct TradingLog {
        uint256 timestamp;
        string  mt4Reference;
        int256  profitUsdt;   // scaled 1e6 (signed)
        address submittedBy;
    }
    TradingLog[] public tradingLogs;

    // Pending withdrawals allocated after distribution
    mapping(address => uint256) public pendingEthReturn;
    mapping(address => uint256) public pendingUsdtReturn;

    bool public returnsDistributed;

    // ─── Events ───────────────────────────────────────────────────────────────
    event Whitelisted(address indexed user, bool status);
    event Deposited(address indexed user, uint256 ethAmount, uint256 usdtAmount);
    event SharesSnapshotted(uint256 snapshotEth, uint256 snapshotUsdt, uint256 depositors);
    event FundsWithdrawnToTrading(address indexed owner, uint256 ethAmount, uint256 usdtAmount);
    event TradingLogSubmitted(uint256 indexed logIndex, string mt4Ref, int256 profitUsdt);
    event ReturnsDeposited(address indexed by, uint256 ethAmount, uint256 usdtAmount);
    event ReturnsDistributed(uint256 totalEth, uint256 totalUsdt, uint256 recipients);
    event UserWithdrew(address indexed user, uint256 ethAmount, uint256 usdtAmount);
    event TraderChanged(address indexed newTrader);
    event CycleReset();
    event Paused(bool status);
    event EmergencyWithdraw(address indexed owner, uint256 ethAmount, uint256 usdtAmount);

    // ─── Modifiers ────────────────────────────────────────────────────────────
    modifier onlyOwner()  { require(msg.sender == owner,  "Not owner");  _; }
    modifier onlyTrader() { require(msg.sender == trader || msg.sender == owner, "Not trader"); _; }
    modifier onlyWhitelisted() { require(whitelist[msg.sender], "Not whitelisted"); _; }
    modifier inPhase(Phase p)  { require(phase == p, "Wrong phase"); _; }

    // ─── Constructor ──────────────────────────────────────────────────────────
    // FIX [6]: Zero-address check on trader
    constructor(address _trader) {
        require(_trader != address(0), "Trader zero address");
        owner  = msg.sender;
        trader = _trader;
        phase  = Phase.OPEN;
        _reentrancyStatus = _NOT_ENTERED;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  OWNER — ADMINISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    function setWhitelist(address[] calldata users, bool status) external onlyOwner {
        for (uint256 i; i < users.length; i++) {
            require(users[i] != address(0), "Zero address in list");
            whitelist[users[i]] = status;
            emit Whitelisted(users[i], status);
        }
    }

    // FIX [6]: Zero-address check
    function setTrader(address _trader) external onlyOwner {
        require(_trader != address(0), "Trader zero address");
        trader = _trader;
        emit TraderChanged(_trader);
    }

    // FIX [8]: Pause toggle — owner can halt all non-emergency operations
    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
    }

    // ─── FIX [3] + [4]: Snapshot BEFORE transfer ─────────────────────────────
    //
    // OLD (vulnerable):
    //   1. Check balance  → 10 ETH
    //   2. [attacker deposits 5 ETH between step 1 and 3]
    //   3. Loop & snapshot shares based on stale deposit totals
    //   4. Transfer funds
    //
    // NEW (fixed):
    //   1. Record current balances
    //   2. Snapshot shares immediately from those balances
    //   3. Transition phase
    //   4. Transfer funds (state already settled)
    //
    function withdrawFundsToTrading()
        external
        onlyOwner
        inPhase(Phase.OPEN)
        whenNotPaused
        nonReentrant
    {
        uint256 ethBal  = address(this).balance;
        uint256 usdtBal = USDT.balanceOf(address(this));
        require(ethBal > 0 || usdtBal > 0, "Nothing to withdraw");

        // FIX [3]: Snapshot shares NOW, before state changes or transfers
        _snapshotEth  = ethBal;
        _snapshotUsdt = usdtBal;

        uint256 n = _depositorList.length;
        for (uint256 i; i < n; i++) {
            address d = _depositorList[i];
            // FIX [7]: ETH and USDT shares computed independently, no cross-decimal math
            // FIX [5]: mulDiv avoids overflow — (a * b) / c done safely
            if (ethBal > 0 && ethDeposited[d] > 0) {
                ethShareOf[d] = mulDiv(ethDeposited[d], SHARE_DENOM, totalEthDeposited);
            }
            if (usdtBal > 0 && usdtDeposited[d] > 0) {
                usdtShareOf[d] = mulDiv(usdtDeposited[d], SHARE_DENOM, totalUsdtDeposited);
            }
        }

        emit SharesSnapshotted(ethBal, usdtBal, n);

        // FIX [3]: Phase transition BEFORE external calls (CEI)
        phase = Phase.TRADING;
        returnsDistributed = false;

        // External calls last — state is fully settled
        if (ethBal > 0)  _safeTransferETH(owner, ethBal);
        if (usdtBal > 0) _safeTransferERC20(USDT, owner, usdtBal);

        emit FundsWithdrawnToTrading(owner, ethBal, usdtBal);
    }

    // Reset cycle after full distribution
    function resetCycle()
        external
        onlyOwner
        inPhase(Phase.RETURNING)
    {
        require(returnsDistributed, "Distribute returns first");

        uint256 n = _depositorList.length;
        for (uint256 i; i < n; i++) {
            address d = _depositorList[i];
            ethDeposited[d]     = 0;
            usdtDeposited[d]    = 0;
            ethShareOf[d]       = 0;
            usdtShareOf[d]      = 0;
            pendingEthReturn[d] = 0;
            pendingUsdtReturn[d]= 0;
            _isDepositor[d]     = false;
        }

        delete _depositorList;
        totalEthDeposited  = 0;
        totalUsdtDeposited = 0;
        _snapshotEth       = 0;
        _snapshotUsdt      = 0;
        phase              = Phase.OPEN;

        emit CycleReset();
    }

    // ─── FIX [8]: Emergency withdraw — bypasses phase, only when paused ───────
    //
    // Allows owner to recover stuck funds if contract enters an unrecoverable
    // state. Requires pause to be active first (forces deliberate action).
    //
    function emergencyWithdraw() external onlyOwner {
        require(paused, "Pause first");

        uint256 ethBal  = address(this).balance;
        uint256 usdtBal = USDT.balanceOf(address(this));

        // CEI: clear state before transfers
        phase = Phase.OPEN;
        returnsDistributed = false;

        if (ethBal > 0)  _safeTransferETH(owner, ethBal);
        if (usdtBal > 0) _safeTransferERC20(USDT, owner, usdtBal);

        emit EmergencyWithdraw(owner, ethBal, usdtBal);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  DEPOSITOR FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    function depositETH()
        external
        payable
        onlyWhitelisted
        inPhase(Phase.OPEN)
        whenNotPaused
    {
        require(msg.value > 0, "Zero ETH");
        _registerDepositor(msg.sender);
        // State update — no external calls follow, so CEI is trivially satisfied
        ethDeposited[msg.sender] += msg.value;
        totalEthDeposited        += msg.value;
        emit Deposited(msg.sender, msg.value, 0);
    }

    function depositUSDT(uint256 amount)
        external
        onlyWhitelisted
        inPhase(Phase.OPEN)
        whenNotPaused
        nonReentrant
    {
        require(amount > 0, "Zero USDT");
        // FIX [2]: Use safe transferFrom wrapper
        _safeTransferFromERC20(USDT, msg.sender, address(this), amount);
        _registerDepositor(msg.sender);
        usdtDeposited[msg.sender] += amount;
        totalUsdtDeposited        += amount;
        emit Deposited(msg.sender, 0, amount);
    }

    function _registerDepositor(address d) internal {
        if (!_isDepositor[d]) {
            _isDepositor[d] = true;
            _depositorList.push(d);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  TRADER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    function submitTradingLog(string calldata mt4Reference, int256 profitUsdt)
        external
        onlyTrader
        whenNotPaused
    {
        tradingLogs.push(TradingLog({
            timestamp:    block.timestamp,
            mt4Reference: mt4Reference,
            profitUsdt:   profitUsdt,
            submittedBy:  msg.sender
        }));
        emit TradingLogSubmitted(tradingLogs.length - 1, mt4Reference, profitUsdt);
    }

    // FIX [4]: Added inPhase(Phase.TRADING) guard
    function depositReturnsUSDT(uint256 amount)
        external
        onlyTrader
        inPhase(Phase.TRADING)  // ← was missing
        whenNotPaused
        nonReentrant
    {
        require(amount > 0, "Zero USDT");
        // FIX [2]: safe transferFrom
        _safeTransferFromERC20(USDT, msg.sender, address(this), amount);
    }

    // Finalize: deposit any ETH returns + trigger distribution
    function depositReturns()
        external
        payable
        onlyTrader
        inPhase(Phase.TRADING)
        whenNotPaused
        nonReentrant
    {
        uint256 ethPool  = address(this).balance;  // includes msg.value
        uint256 usdtPool = USDT.balanceOf(address(this));
        require(ethPool > 0 || usdtPool > 0, "No returns to distribute");

        // FIX [3]: CEI — update phase & pending amounts BEFORE any transfers
        phase = Phase.RETURNING;
        _distributeReturns(ethPool, usdtPool);

        emit ReturnsDeposited(msg.sender, msg.value, usdtPool);
    }

    // Distribute without additional ETH (USDT already deposited via depositReturnsUSDT)
    function distributeReturnsManually()
        external
        onlyTrader
        inPhase(Phase.TRADING)
        whenNotPaused
        nonReentrant
    {
        uint256 ethPool  = address(this).balance;
        uint256 usdtPool = USDT.balanceOf(address(this));
        require(ethPool > 0 || usdtPool > 0, "Nothing to distribute");

        // CEI — update state before any possibility of external interaction
        phase = Phase.RETURNING;
        _distributeReturns(ethPool, usdtPool);
    }

    function _distributeReturns(uint256 ethPool, uint256 usdtPool) internal {
        uint256 n = _depositorList.length;
        for (uint256 i; i < n; i++) {
            address d = _depositorList[i];
            // FIX [7]: ETH share applied only to ETH pool, USDT share to USDT pool
            if (ethPool > 0 && ethShareOf[d] > 0) {
                pendingEthReturn[d]  = mulDiv(ethPool,  ethShareOf[d],  SHARE_DENOM);
            }
            if (usdtPool > 0 && usdtShareOf[d] > 0) {
                pendingUsdtReturn[d] = mulDiv(usdtPool, usdtShareOf[d], SHARE_DENOM);
            }
        }
        returnsDistributed = true;
        emit ReturnsDistributed(ethPool, usdtPool, n);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  USER WITHDRAWAL
    // ═══════════════════════════════════════════════════════════════════════════

    // FIX [1] + [3]: nonReentrant + full CEI — zero state THEN call externals
    function withdraw()
        external
        inPhase(Phase.RETURNING)
        whenNotPaused
        nonReentrant
    {
        require(returnsDistributed, "Returns not distributed yet");

        uint256 ethAmt  = pendingEthReturn[msg.sender];
        uint256 usdtAmt = pendingUsdtReturn[msg.sender];
        require(ethAmt > 0 || usdtAmt > 0, "Nothing to withdraw");

        // FIX [3]: Zero state BEFORE any external calls (CEI)
        pendingEthReturn[msg.sender]  = 0;
        pendingUsdtReturn[msg.sender] = 0;

        // External calls — reentrancy guard active, state already cleared
        if (ethAmt > 0)  _safeTransferETH(msg.sender, ethAmt);
        if (usdtAmt > 0) _safeTransferERC20(USDT, msg.sender, usdtAmt);

        emit UserWithdrew(msg.sender, ethAmt, usdtAmt);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  FIX [2]: SAFE TRANSFER HELPERS
    //
    //  USDT (and many ERC-20s) may:
    //    (a) return false instead of reverting on failure, OR
    //    (b) return nothing at all (non-standard)
    //
    //  We use low-level `call` and validate the return data explicitly,
    //  matching the approach of OpenZeppelin's SafeERC20.
    // ═══════════════════════════════════════════════════════════════════════════

    function _safeTransferERC20(IERC20 token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(token.transfer.selector, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "ERC20 transfer failed");
    }

    function _safeTransferFromERC20(IERC20 token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(token.transferFrom.selector, from, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "ERC20 transferFrom failed");
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  FIX [5]: mulDiv — overflow-safe (a * b) / c
    //
    //  Even though Solidity 0.8.x reverts on overflow, (a * b) can still
    //  overflow uint256 before the division. This helper splits the
    //  multiplication to avoid it.
    // ═══════════════════════════════════════════════════════════════════════════

    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        require(denominator > 0, "mulDiv: zero denominator");
        // If a or b is small enough that a*b won't overflow, do it directly
        if (a == 0 || b == 0) return 0;
        // Check if multiplication would overflow
        unchecked {
            // Fast path: multiply and verify no overflow occurred
            uint256 fastResult = a * b;
            if (fastResult / a == b) {
                return fastResult / denominator;
            }
        }
        // Slow path: use 512-bit intermediate via mulmod
        // result = floor(a * b / denominator)
        uint256 remainder;
        uint256 result;
        assembly {
            // 512-bit multiply: [prod1, prod0] = a * b
            let mm  := mulmod(a, b, not(0))
            let p0  := mul(a, b)
            let p1  := sub(sub(mm, p0), lt(mm, p0))
            // Subtract remainder
            remainder := mulmod(a, b, denominator)
            result    := sub(p1, gt(remainder, p0))
            p0        := sub(p0, remainder)
            // Factor powers of two out of denominator
            let twos  := and(sub(0, denominator), denominator)
            denominator := div(denominator, twos)
            p0        := div(p0, twos)
            twos      := add(div(sub(0, twos), twos), 1)
            p0        := or(p0, mul(result, twos))
            // Invert denominator mod 2^256
            let inv   := xor(mul(3, denominator), 2)
            inv       := mul(inv, sub(2, mul(denominator, inv)))
            inv       := mul(inv, sub(2, mul(denominator, inv)))
            inv       := mul(inv, sub(2, mul(denominator, inv)))
            inv       := mul(inv, sub(2, mul(denominator, inv)))
            inv       := mul(inv, sub(2, mul(denominator, inv)))
            inv       := mul(inv, sub(2, mul(denominator, inv)))
            result    := mul(p0, inv)
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  VIEW HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function getDepositorCount() external view returns (uint256) { return _depositorList.length; }
    function getDepositor(uint256 i) external view returns (address) { return _depositorList[i]; }
    function getTradingLogCount() external view returns (uint256) { return tradingLogs.length; }

    function getLatestLog() external view returns (TradingLog memory) {
        require(tradingLogs.length > 0, "No logs");
        return tradingLogs[tradingLogs.length - 1];
    }

    function myPendingReturns() external view returns (uint256 eth, uint256 usdt) {
        return (pendingEthReturn[msg.sender], pendingUsdtReturn[msg.sender]);
    }

    function contractBalances() external view returns (uint256 eth, uint256 usdt) {
        return (address(this).balance, USDT.balanceOf(address(this)));
    }

    function phaseName() external view returns (string memory) {
        if (phase == Phase.OPEN)      return "OPEN";
        if (phase == Phase.TRADING)   return "TRADING";
        if (phase == Phase.RETURNING) return "RETURNING";
        return "UNKNOWN";
    }

    receive() external payable {}
}
