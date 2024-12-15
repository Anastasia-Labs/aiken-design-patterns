/// Every list node utxo:
/// - has a unique `key` (unless it's the root node)
/// - has a unique `link` to another node's key 
///   (unless it's the last node of the list)
/// - holds some app-specific `data`
pub type NodeDatum {
  key: NodeKey,
  link: NodeKey,
  data: Data,
}

/// Same as `Option`, but with more informative constructor names.
pub type NodeKey {
  Key { key: ByteArray }
  Empty
}
