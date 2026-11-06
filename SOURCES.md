# Sources

All quotes were read from the primary documents below on 2026-11-06. SHA256
values are of the copies fetched for this work (not committed here).

## OpenSSH PROTOCOL, tag V_9_6_P1

- URL: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/PROTOCOL
  (commit b24f772e2198a18375906f1c3020d11dff8770b0)
- SHA256 of fetched file: 6dc7d438541a928734281de9568ccce61222490bfa3b6c49901781be03d5d41a
- Section "1.9 transport: strict key exchange extension" (at this tag the file
  also has a "1.9 transport: ping facility" section; cite by title).

> These pseudo-algorithms are only valid in the initial SSH2_MSG_KEXINIT and
> MUST be ignored if they are present in subsequent SSH2_MSG_KEXINIT packets.

> a) During initial KEX, terminate the connection if any unexpected or
> out-of-sequence packet is received. This includes terminating the
> connection if the first packet received is not SSH2_MSG_KEXINIT.
> Unexpected packets for the purpose of strict KEX include messages
> that are otherwise valid at any time during the connection such as
> SSH2_MSG_DEBUG and SSH2_MSG_IGNORE.
> b) After sending or receiving a SSH2_MSG_NEWKEYS message, reset the
> packet sequence number to zero. This behaviour persists for the
> duration of the connection (i.e. not just the first
> SSH2_MSG_NEWKEYS).

Used for: markers, initial-only negotiation, countermeasures (a) and (b),
reset at every NEWKEYS (fixtures 03, 13, 15, 16, 17).

## OpenSSH 9.6 release notes

- URL: https://www.openssh.com/txt/release-9.6
- SHA256 of fetched file: f6f27e84cfc0f476ef7717e4e2bbd46fda48ca67d8abc6c4a6e3ac4bf29c452b

> This attack allows a MITM to effect a limited break of the integrity of the
> early encrypted SSH transport protocol by sending extra messages prior to
> the commencement of encryption, and deleting an equal number of consecutive
> messages immediately after encryption starts.

> The most serious identified impact is that it lets a MITM to delete the
> SSH2_MSG_EXT_INFO message sent before authentication starts

> "strict KEX" protocol extension that will be automatically enabled when both
> the client and server support it.

> Either of these changes should be sufficient to thwart the Terrapin Attack.

Used for: the attack shape (inject before NEWKEYS, drop EXT_INFO after), the
bilateral condition (fixtures 09, 10), and the expectation that (a) alone and
(b) alone each stop the edit (fixtures 07, 08).

## RFC 4253

- URL: https://www.rfc-editor.org/rfc/rfc4253.txt
- SHA256 of fetched file: b471173305154f6c66facffcf7a4a25fc5c32765cb30542120be6c20a88f1ed3
- §6.4:

> The sequence_number is initialized to zero for the first packet, and is
> incremented after every packet (regardless of whether encryption or MAC is
> in use). It is never reset, even if keys/algorithms are renegotiated later.
> It wraps around to zero after every 2^32 packets.

- §8: H includes `I_C, the payload of the client's SSH_MSG_KEXINIT` and
  `I_S, the payload of the server's SSH_MSG_KEXINIT`.
- §7.1 (messages allowed during key exchange) and §11.2 (SSH_MSG_IGNORE) are
  the legacy behaviour the model reproduces when strict is off.

Used for: legacy counter behaviour, wraparound test, KEXINIT tamper detection
(fixtures 11, 12).

## RFC 5647

- URL: https://www.rfc-editor.org/rfc/rfc5647.txt
- SHA256 of fetched file: a0ee7571f0fa4a2bda1819a2057cf9f83277b90b0fe6cab91be216dfb177aabd
- §7.1:

> The invocation field is treated as a 64-bit integer and is incremented after
> each invocation of AES-GCM to process a binary packet.

Used for: the `InvocationCounter` binding (fixture 05).

## CVE identifier

- CVE-2023-48795: https://www.cve.org/CVERecord?id=CVE-2023-48795
