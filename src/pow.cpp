// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <math.h>
#include <primitives/block.h>
#include <uint256.h>


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int nHeight = pindexLast->nHeight + 1;

    if (nHeight < 26850)
        return GetNextWorkRequiredLegacy(pindexLast, pblock, params);
    if (nHeight >= 26850 && nHeight < 1100000)
        return KimotoGravityWell(pindexLast, pblock, params);
    if (nHeight >= 1100000 && nHeight < 1250000)
        return DigiShield(pindexLast, pblock, params);
    if (nHeight >= 1250000 && nHeight < 1250008)
        return UintToArith256(params.powLimit).GetCompact();
    return DUAL_KGW3(pindexLast, pblock, params);
}

//! required for kgw (credit goes to dash, code @ https://github.com/mooncoindev/mooncoin/blob/master/src/main.cpp#L2694-L2710)
double ConvertBitsToDouble(unsigned int nBits)
{
    int nShift = (nBits >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

unsigned int GetNextWorkRequiredLegacy(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    arith_uint256 nProofOfWorkLimit = UintToArith256(params.powLimit);

    // Genesis block
    if (pindexLast == nullptr)
        return nProofOfWorkLimit.GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit.GetCompact();
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();

    if (pindexLast->nHeight + 1 > 10000) {
        if (nActualTimespan < params.nPowTargetTimespan / 4)
            nActualTimespan = params.nPowTargetTimespan / 4;
        if (nActualTimespan > params.nPowTargetTimespan * 4)
            nActualTimespan = params.nPowTargetTimespan * 4;
    } else if (pindexLast->nHeight + 1 > 5000) {
        if (nActualTimespan < params.nPowTargetTimespan / 8)
            nActualTimespan = params.nPowTargetTimespan / 8;
        if (nActualTimespan > params.nPowTargetTimespan * 4)
            nActualTimespan = params.nPowTargetTimespan * 4;
    } else {
        if (nActualTimespan < params.nPowTargetTimespan / 16)
            nActualTimespan = params.nPowTargetTimespan / 16;
        if (nActualTimespan > params.nPowTargetTimespan * 4)
            nActualTimespan = params.nPowTargetTimespan * 4;
    }

    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (bnNew > nProofOfWorkLimit)
        bnNew = nProofOfWorkLimit;

    return bnNew.GetCompact();
}

unsigned int KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    const CBlockIndex* BlockLastSolved = pindexLast;
    const CBlockIndex* BlockReading = pindexLast;
    uint64_t PastBlocksMin = 240;
    uint64_t PastBlocksMax = 6720;
    uint64_t PastBlocksMass = 0;
    int64_t PastRateActualSeconds = 0;
    int64_t PastRateTargetSeconds = 0;
    double PastRateAdjustmentRatio = double(1);
    arith_uint256 PastDifficultyAverage;
    arith_uint256 PastDifficultyAveragePrev;
    double EventHorizonDeviation;
    double EventHorizonDeviationFast;
    double EventHorizonDeviationSlow;
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    if (BlockLastSolved == nullptr ||
        BlockLastSolved->nHeight == 0 ||
        (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) {
        return bnPowLimit.GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) break;

        PastBlocksMass++;

        if (i == 1) {
            PastDifficultyAverage.SetCompact(BlockReading->nBits);
        } else if (arith_uint256().SetCompact(BlockReading->nBits) >= PastDifficultyAveragePrev) {
            PastDifficultyAverage = ((arith_uint256().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
        } else {
            PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - arith_uint256().SetCompact(BlockReading->nBits)) / i);
        }

        PastDifficultyAveragePrev = PastDifficultyAverage;
        PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds = params.nPowTargetSpacing * PastBlocksMass;
        PastRateAdjustmentRatio = double(1);

        if (PastRateActualSeconds < 0) PastRateActualSeconds = 0;

        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0)
            PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);

        EventHorizonDeviation = 1 + (0.7084 * pow((double(PastBlocksMass) / double(144)), -1.228));
        EventHorizonDeviationFast = EventHorizonDeviation;
        EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin) {
            if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
                assert(BlockReading);
                break;
            }
        }

        if (BlockReading->pprev == nullptr) {
            assert(BlockReading);
            break;
        }

        BlockReading = BlockReading->pprev;
    }

    arith_uint256 bnNew(PastDifficultyAverage);

    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
        bnNew *= PastRateActualSeconds;
        bnNew /= PastRateTargetSeconds;
    }

    if (bnNew > bnPowLimit) bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int DigiShield(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const arith_uint256 bnProofOfWorkLimit = UintToArith256(params.powLimit);
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    const int blockstogoback = 1;
    int64_t retargetTimespan = 90;

    // Genesis block
    if (pindexLast == nullptr)
        return nProofOfWorkLimit;

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;

    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    if (nActualTimespan < (retargetTimespan - (retargetTimespan/4)) ) nActualTimespan = (retargetTimespan - (retargetTimespan/4));
    if (nActualTimespan > (retargetTimespan + (retargetTimespan/2)) ) nActualTimespan = (retargetTimespan + (retargetTimespan/2));

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= retargetTimespan;
    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    return bnNew.GetCompact();
}

unsigned int DUAL_KGW3(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    int64_t PastBlocksMass = 0;
    int64_t PastRateActualSeconds = 0;
    int64_t PastRateTargetSeconds = 0;
    double PastRateAdjustmentRatio = double(1);
    arith_uint256 PastDifficultyAverage;
    arith_uint256 PastDifficultyAveragePrev;
    double EventHorizonDeviation;
    double EventHorizonDeviationFast;
    double EventHorizonDeviationSlow;
    static const int64_t Blocktime = params.nPowTargetSpacing;
    static const unsigned int timeDaySeconds = 86400;
    int64_t pastSecondsMin = timeDaySeconds * 0.025;
    int64_t pastSecondsMax = timeDaySeconds * 7;
    int64_t PastBlocksMin = pastSecondsMin / Blocktime;
    int64_t PastBlocksMax = pastSecondsMax / Blocktime;
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    if (BlockLastSolved == nullptr || BlockLastSolved->nHeight == 0 ||
        (int64_t)BlockLastSolved->nHeight < PastBlocksMin) {
        return bnPowLimit.GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) {
            break;
        }

        PastBlocksMass++;
        PastDifficultyAverage.SetCompact(BlockReading->nBits);

        if (i > 1) {
            if(PastDifficultyAverage >= PastDifficultyAveragePrev)
                PastDifficultyAverage = ((PastDifficultyAverage - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
            else
                PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - PastDifficultyAverage) / i);
        }

        PastDifficultyAveragePrev = PastDifficultyAverage;
        PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds = Blocktime * PastBlocksMass;
        PastRateAdjustmentRatio = double(1);

        if (PastRateActualSeconds < 0) {
            PastRateActualSeconds = 0;
        }

        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
        }

        EventHorizonDeviation = 1 + (0.7084 * pow((double(PastBlocksMass)/double(72)), -1.228));
        EventHorizonDeviationFast = EventHorizonDeviation;
        EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin) {
            if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
                assert(BlockReading);
                break;
            }
        }

        if (BlockReading->pprev == nullptr) {
            assert(BlockReading);
            break;
        }

        BlockReading = BlockReading->pprev;
    }

    arith_uint256 kgw_dual1(PastDifficultyAverage);
    arith_uint256 kgw_dual2;
    kgw_dual2.SetCompact(pindexLast->nBits);

    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
        kgw_dual1 *= PastRateActualSeconds;
        kgw_dual1 /= PastRateTargetSeconds;
    }

    int64_t nActualTime1 = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
    int64_t nActualTimespanshort = nActualTime1;

    if(nActualTime1 < 0) {
        nActualTime1 = Blocktime;
    }

    if (nActualTime1 < Blocktime / 3)
        nActualTime1 = Blocktime / 3;

    if (nActualTime1 > Blocktime * 3)
        nActualTime1 = Blocktime * 3;

    kgw_dual2 *= nActualTime1;
    kgw_dual2 /= Blocktime;
    arith_uint256 bnNew;
    bnNew = ((kgw_dual2 + kgw_dual1) /2 );

    if(nActualTimespanshort < Blocktime / 6) {
        const int nLongShortNew1 = 85;
        const int nLongShortNew2 = 100;
        bnNew = bnNew * nLongShortNew1;
        bnNew = bnNew / nLongShortNew2;
    }

    const int nLongTimeLimit = 60 * 60;

    if ((pblock-> nTime - pindexLast->GetBlockTime()) > nLongTimeLimit) {
        bnNew = bnPowLimit/15;
    }

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
