// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <banned.h>

#include <script/script.h>
#include <validation.h>

std::vector<CScript> bannedPubKeys;

void populateBanned()
{
        std::string bannedScripts[4] = { "76a914ffc824a400e59fe4aaf53d54fd784d70ae8e2f1b88ac",
                                         "76a9141d41eef4d357c9269d002f64641b93a4ad79c90288ac",
                                         "76a91403c188fba341ecb2d8e0edbca68bcc3cf461610c88ac",
                                         "76a91438670470c4224a7e3c96075bb910f8029cb377e688ac" };

        for (unsigned int i = 0; i < 4; i++) {
	   CScript bannedEntry;
           bannedEntry << ParseHex(bannedScripts[i]);
           bannedPubKeys.push_back(bannedEntry);
        }

        assert(bannedPubKeys.size() == 4);
}

bool isBannedScript(const CScript &keyTest)
{
	for (const auto& bannedScript : bannedPubKeys)
	   if (bannedScript == keyTest)
               return true;
        return false;
}
