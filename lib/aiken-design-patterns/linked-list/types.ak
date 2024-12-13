pub type NodeKey {
  Key { key: ByteArray }
  Empty
}

pub type NodeDatum {
  key: NodeKey,
  link: NodeKey,
  data: Data,
}
