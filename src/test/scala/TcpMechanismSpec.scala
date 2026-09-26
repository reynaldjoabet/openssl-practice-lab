class TcpMechanismSpec extends munit.FunSuite {
  test("orders out-of-order segments by sequence number") {
    val receiver = new TcpReceiver(initialRcvNxt = 100)

    receiver.receive(TcpSegment(104, "efgh"))
    val state = receiver.receive(TcpSegment(100, "abcd"))

    assertEquals(state.delivered, Vector("abcd", "efgh"))
    assertEquals(state.rcvNxt, 108L)
  }

  test("drops retransmitted segments below rcv_nxt") {
    val receiver = new TcpReceiver(initialRcvNxt = 100)

    receiver.receive(TcpSegment(100, "abcd"))
    val state = receiver.receive(TcpSegment(100, "abcd"))

    assertEquals(state.delivered, Vector("abcd"))
    assertEquals(state.rcvNxt, 104L)
  }

  test("turns a received gap into a duplicate ACK for rcv_nxt") {
    val receiver = new TcpReceiver(initialRcvNxt = 100)

    val state = receiver.receive(TcpSegment(104, "efgh"))

    assertEquals(state.duplicateAcks, Vector(100L))
    assertEquals(state.rcvNxt, 100L)
  }

  test("fast retransmits after three duplicate ACKs") {
    val sender = TcpSender(SendWindow(sndUna = 1000, size = 500))

    assertEquals(sender.fastRetransmit(Seq(1000L, 1000L, 1000L)), Some(1000L))
  }

  test("measures the send window from snd_una") {
    val sender = TcpSender(SendWindow(sndUna = 1000, size = 500))

    assert(sender.canSend(1000))
    assert(sender.canSend(1499))
    assert(!sender.canSend(999))
    assert(!sender.canSend(1500))
  }

  test("accepts injected segments only inside the current window") {
    val window = SendWindow(sndUna = 2000, size = 100)

    assert(window.contains(2000))
    assert(window.contains(2099))
    assert(!window.contains(1999))
    assert(!window.contains(2100))
  }
}
