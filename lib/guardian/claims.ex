defmodule Guardian.Claims do
  @moduledoc false
  import Guardian.Utils

  @doc false
  def app_claims, do: %{"iss" => Guardian.issuer} |> iat |> jti

  @doc false
  def app_claims(existing_claims) do
    Map.merge(app_claims, Enum.into(existing_claims, %{}))
  end

  @doc """
  Encodes permissions into the claims set.
  Permissions are stored at the :pem key as a map of <type> => <value as int>
  """
  def permissions(claims, perm_list) do
    perms = %{}
    |> Enum.into(perm_list)
    |> Enum.reduce(%{}, fn({key, list}, acc) ->
      Map.put(
        acc,
        to_string(key),
        Guardian.Permissions.to_value(list, key)
      )
    end)
    Map.put(claims, "pem", perms)
  end

  @doc false
  def typ(claims, nil), do: typ(claims, "token")
  @doc false
  def typ(claims, type) when is_atom(type), do: typ(claims, to_string(type))
  @doc false
  def typ(claims, type), do: Map.put(claims, "typ", type)

  @doc false
  def aud(claims, nil), do: aud(claims, Guardian.config(:issuer))
  @doc false
  def aud(claims, audience) when is_atom(audience) do
    aud(claims, to_string(audience))
  end

  @doc false
  def aud(claims, audience), do: Map.put(claims, "aud", audience)

  @doc false
  def sub(claims, subject) when is_atom(subject) do
    sub(claims, to_string(subject))
  end

  @doc false
  def sub(claims, subject), do: Map.put(claims, "sub", subject)

  @doc false
  def jti(claims), do: jti(claims, :uuid.get_v4 |> uuid_to_string(:default))

  @doc false
  def jti(claims, id) when is_atom(id), do: sub(claims, to_string(id))
  @doc false
  def jti(claims, id), do: Map.put(claims, "jti", id)

  @doc false
  def nbf(claims), do: Map.put(claims, "nbf", timestamp - 1)
  @doc false
  def nbf(claims, ts), do: Map.put(claims, "nbf", ts)

  @doc false
  def iat(claims), do: Map.put(claims, "iat", timestamp)
  @doc false
  def iat(claims, ts), do: Map.put(claims, "iat", ts)

  @doc false
  def ttl(claims = %{"exp" => _exp}), do: claims

  @doc false
  def ttl(claims = %{"ttl" => requested_ttl}) do
    claims
    |> Map.delete("ttl")
    |> ttl(requested_ttl)
  end

  @doc false
  def ttl(claims) do
    ttl(claims, Guardian.config(:ttl, {1_000_000_000, :seconds}))
  end

  @doc false
  def ttl(%{"iat" => iat_v} = the_claims, requested_ttl) do
    assign_exp_from_ttl(the_claims, {iat_v, requested_ttl})
  end

  @doc false
  def ttl(the_claims, requested_ttl) do
    the_claims
    |> iat
    |> ttl(requested_ttl)
  end

  defp assign_exp_from_ttl(the_claims, {nil, _}) do
    Map.put_new(the_claims, timestamp + 1_000_000_000)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {millis, unit}})
  when unit in [:milli, :millis] do
    Map.put(the_claims, "exp", iat_v + millis / 1000)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {seconds, unit}})
  when unit in [:second, :seconds] do
    Map.put(the_claims, "exp", iat_v + seconds)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {minutes, unit}})
  when unit in [:minute, :minutes] do
    Map.put(the_claims, "exp", iat_v + minutes * 60)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {hours, unit}})
  when unit in [:hour, :hours] do
    Map.put(the_claims, "exp", iat_v + hours * 60 * 60)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {days, unit}})
  when unit in [:day, :days] do
    Map.put(the_claims, "exp", iat_v + days * 24 * 60 * 60)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {years, unit}})
  when unit in [:year, :years] do
    Map.put(the_claims, "exp", iat_v + years * 365 * 24 * 60 * 60)
  end

  defp assign_exp_from_ttl(_, {_iat_v, {_, units}}) do
    raise "Unknown Units: #{units}"
  end

  defp assign_exp_from_ttl(the_claims, _), do: the_claims


  defp uuid_to_string(<<u0::32, u1::16, u2::16, u3::16, u4::48>>, :default) do
    [binary_to_hex_list(<<u0::32>>), ?-, binary_to_hex_list(<<u1::16>>), ?-,
     binary_to_hex_list(<<u2::16>>), ?-, binary_to_hex_list(<<u3::16>>), ?-,
     binary_to_hex_list(<<u4::48>>)]
      |> IO.iodata_to_binary
  end

  defp binary_to_hex_list(binary) do
    :binary.bin_to_list(binary)
      |> list_to_hex_str
  end

  # Hex string to hex character list.
  defp hex_str_to_list([]) do
    []
  end

  defp list_to_hex_str([]) do
    []
  end

  defp list_to_hex_str([head | tail]) do
    to_hex_str(head) ++ list_to_hex_str(tail)
  end

  # Hex character integer to hex string.
  defp to_hex_str(n) when n < 256 do
    [to_hex(div(n, 16)), to_hex(rem(n, 16))]
  end

  # Integer to hex character.
  defp to_hex(i) when i < 10 do
    0 + i + 48
  end

  defp to_hex(i) when i >= 10 and i < 16 do
    ?a + (i - 10)
  end

  # Hex character to integer.
  defp to_int(c) when ?0 <= c and c <= ?9 do
    c - ?0
  end

  defp to_int(c) when ?A <= c and c <= ?F do
    c - ?A + 10
  end

  defp to_int(c) when ?a <= c and c <= ?f do
    c - ?a + 10
  end

end
