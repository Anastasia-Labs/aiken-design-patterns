use aiken/collection/dict.{Dict}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{Output}

pub type NodeKey {
  Key { key: ByteArray }
  Empty
}

pub type NodeDatum {
  key: NodeKey,
  link: NodeKey,
  data: Data,
}

pub type Common {
  node_cs: PolicyId,
  node_mint: Dict<AssetName, Int>,
  node_in_outputs: List<Output>,
  node_outputs: List<Output>,
}
