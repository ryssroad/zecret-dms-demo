//! Network selection shared by all roles.

use anyhow::{Result, bail};
use zcash_protocol::consensus::{BlockHeight, Network, NetworkType, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

/// Network selected on the command line.
///
/// The local regtest parameter set activates every upgrade through NU6.3 at height 1.
#[derive(Clone, Copy, Debug)]
pub enum Net {
    Main,
    Test,
    Regtest(LocalNetwork),
}

impl Net {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "main" => Net::Main,
            "test" => Net::Test,
            "regtest" => {
                let h = Some(BlockHeight::from_u32(1));
                Net::Regtest(LocalNetwork {
                    overwinter: h,
                    sapling: h,
                    blossom: h,
                    heartwood: h,
                    canopy: h,
                    nu5: h,
                    nu6: h,
                    nu6_1: h,
                    nu6_2: h,
                    nu6_3: h,
                })
            }
            other => bail!("unknown network {other:?}, expected main|test|regtest"),
        })
    }
}

impl Parameters for Net {
    fn network_type(&self) -> NetworkType {
        match self {
            Net::Main => NetworkType::Main,
            Net::Test => NetworkType::Test,
            Net::Regtest(_) => NetworkType::Regtest,
        }
    }

    fn activation_height(
        &self,
        nu: zcash_protocol::consensus::NetworkUpgrade,
    ) -> Option<BlockHeight> {
        match self {
            Net::Main => Network::MainNetwork.activation_height(nu),
            Net::Test => Network::TestNetwork.activation_height(nu),
            Net::Regtest(local) => local.activation_height(nu),
        }
    }
}
