package example

final case class TcpSegment(sequence: Long, payload: String)

final case class TcpState(
    rcvNxt: Long,
    delivered: Vector[String],
    duplicateAcks: Vector[Long]
)

final case class SendWindow(sndUna: Long, size: Long) {
  require(size >= 0, "window size must be non-negative")

  def contains(sequence: Long): Boolean =
    sequence >= sndUna && sequence < sndUna + size
}

/** A small sequence-space model of the TCP receive-side mechanisms. */
final class TcpReceiver(initialRcvNxt: Long) {
  require(initialRcvNxt >= 0, "initial receive sequence must be non-negative")

  private var state = TcpState(initialRcvNxt, Vector.empty, Vector.empty)
  private var pending = Map.empty[Long, TcpSegment]

  def snapshot: TcpState = state

  def receive(segment: TcpSegment): TcpState = {
    if (segment.sequence < state.rcvNxt) {
      state
    } else if (segment.sequence > state.rcvNxt) {
      pending = pending.updated(segment.sequence, segment)
      state = state.copy(duplicateAcks = state.duplicateAcks :+ state.rcvNxt)
      state
    } else {
      deliver(segment)
      drainPending()
      state
    }
  }

  private def deliver(segment: TcpSegment): Unit = {
    state = state.copy(
      rcvNxt = state.rcvNxt + segment.payload.length,
      delivered = state.delivered :+ segment.payload
    )
  }

  private def drainPending(): Unit = {
    pending.get(state.rcvNxt).foreach { segment =>
      pending -= state.rcvNxt
      deliver(segment)
      drainPending()
    }
  }
}

final case class TcpSender(
    window: SendWindow,
    fastRetransmitThreshold: Int = 3
) {
  require(
    fastRetransmitThreshold > 0,
    "fast retransmit threshold must be positive"
  )

  def canSend(sequence: Long): Boolean = window.contains(sequence)

  def fastRetransmit(acknowledgements: Seq[Long]): Option[Long] = {
    val duplicateAcks = acknowledgements.groupBy(identity).collect {
      case (ack, values) if values.size >= fastRetransmitThreshold => ack
    }
    duplicateAcks.toSeq.sortBy(identity).headOption
  }
}
