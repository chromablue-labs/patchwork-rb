require "test_helper"

class SubjectTest < Minitest::Test
  Membership = Patchwork::Subject.define(:user_id, :workspace_id)
  Slack = Patchwork::Subject.define(:team_id, :user_id, prefix: "slack")
  Ticket = Patchwork::Subject.define(:ticket_id, prefix: "ticket")
  Piped = Patchwork::Subject.define(:org, :user, :project, delimiter: "|")

  def test_validate_accepts_any_non_empty_string
    [ "usr_1", "usr_1:ws_1", "job:nightly-recon", "ws_acme" ].each do |subject|
      assert_equal subject, Patchwork::Subject.validate!(subject)
    end
  end

  def test_validate_rejects_empty_non_strings_and_padding
    [ nil, "", " ", "usr_1 ", "\tusr_1", 1, :usr_1 ].each do |subject|
      assert_raises(ArgumentError, "accepted #{subject.inspect}") { Patchwork::Subject.validate!(subject) }
    end
  end

  def test_two_part_round_trip
    subject = Membership.encode(user_id: "usr_9f2", workspace_id: "ws_acme")

    assert_equal "usr_9f2:ws_acme", subject
    ref = Membership.decode(subject)
    assert_equal "usr_9f2", ref.user_id
    assert_equal "ws_acme", ref.workspace_id
  end

  def test_order_comes_from_the_definition_not_the_call_site
    assert_equal "u:w", Membership.encode(workspace_id: "w", user_id: "u")
  end

  def test_single_part_with_a_prefix
    assert_equal "ticket:8821", Ticket.encode(ticket_id: 8821)
    assert_equal "8821", Ticket.decode("ticket:8821").ticket_id
    assert_nil Ticket.decode("8821")
    assert_nil Ticket.decode("job:8821")
  end

  def test_three_parts_with_a_prefix
    assert_equal "slack:T04AB:U0APP", Slack.encode(team_id: "T04AB", user_id: "U0APP")
    assert_equal "U0APP", Slack.decode("slack:T04AB:U0APP").user_id
  end

  def test_a_custom_delimiter
    subject = Piped.encode(org: "o:1", user: "u:2", project: "p:3")

    assert_equal "o:1|u:2|p:3", subject
    assert_equal "u:2", Piped.decode(subject).user
  end

  def test_encode_refuses_a_part_containing_the_delimiter
    error = assert_raises(ArgumentError) { Membership.encode(user_id: "user:1", workspace_id: "ws") }
    assert_includes error.message, "user_id"
  end

  def test_encode_refuses_missing_unknown_empty_and_padded_parts
    assert_raises(ArgumentError) { Membership.encode(user_id: "u") }
    assert_raises(ArgumentError) { Membership.encode(user_id: "u", workspace_id: "w", project: "p") }
    assert_raises(ArgumentError) { Membership.encode(user_id: "", workspace_id: "w") }
    assert_raises(ArgumentError) { Membership.encode(user_id: nil, workspace_id: "w") }
    assert_raises(ArgumentError) { Membership.encode(user_id: "u ", workspace_id: "w") }
  end

  def test_decode_never_guesses
    [ nil, 42, "", "usr_1", "usr_1:", ":ws_1", "usr_1:ws_1:extra", "usr_1: ws_1", "usr_1::ws_1" ].each do |value|
      assert_nil Membership.decode(value), "decoded #{value.inspect}"
      refute Membership.match?(value)
    end
  end

  def test_decode_bang_raises_unknown_subject
    assert_raises(Patchwork::UnknownSubject) { Membership.decode!("not-a-membership") }
  end

  def test_decoded_refs_are_frozen
    assert Membership.decode("u:w").frozen?
  end

  def test_definition_errors
    assert_raises(ArgumentError) { Patchwork::Subject.define }
    assert_raises(ArgumentError) { Patchwork::Subject.define("user_id") }
    assert_raises(ArgumentError) { Patchwork::Subject.define(:a, :a) }
    assert_raises(ArgumentError) { Patchwork::Subject.define(:a, delimiter: "") }
    assert_raises(ArgumentError) { Patchwork::Subject.define(:a, prefix: "has:colon") }
  end

  def test_inspect_shows_the_shape
    assert_equal "#<Patchwork::Subject slack:<team_id>:<user_id>>", Slack.inspect
  end
end
