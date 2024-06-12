#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

static const unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS = 100;

/** The maximum size in bytes of a standard witnessScript */
static const unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;

/** The maximum weight for transactions we're willing to relay/mine */
static constexpr int32_t MAX_STANDARD_TX_WEIGHT{400000};

#endif
