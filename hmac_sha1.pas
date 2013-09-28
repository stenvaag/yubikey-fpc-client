unit hmac_sha1;

{$mode objfpc}{$H+}

interface

uses
  sha1;

function hmac_sha1(const key, msg: String): TSHA1Digest;
function b64_hmac_sha1(const key, msg: String): String;
function hex_hmac_sha1(const key, msg: String): String;
function hmac_sha1_test: Boolean;

implementation

uses
  base64;

function hmac_sha1(const key, msg: String): TSHA1Digest;
var
   i, keylen : Integer;
   ctx	  : TSHA1Context;
   key_pad, o_key_pad, i_key_pad : array[0..63] of Byte;
begin
  keylen := Length(key);
  FillChar(key_pad[0], SizeOf(key_pad), 0);
  if keylen > 64 then
  begin
     Result := SHA1String(key);
     Move(Result[0], key_pad[0], SizeOf(Result));
  end
  else
    Move(key[1], key_pad[0], keylen);
  for i := 0 to SizeOf(key_pad) - 1 do
  begin
    o_key_pad[i] := key_pad[i] xor $5c;
    i_key_pad[i] := key_pad[i] xor $36;
  end;
  //-
  SHA1Init(ctx);
  SHA1Update(ctx, i_key_pad[0], SizeOf(i_key_pad));
  SHA1Update(ctx, msg[1], Length(msg));
  SHA1Final(ctx, Result);
  //-
  SHA1Init(ctx);
  SHA1Update(ctx, o_key_pad[0], SizeOf(o_key_pad));
  SHA1Update(ctx, Result[0], SizeOf(Result));
  SHA1Final(ctx, Result);
end;

function b64_hmac_sha1(const key, msg: String): String;
var
   digest : TSHA1Digest;
begin
   digest := hmac_sha1(key, msg);
   SetLength(Result, SizeOf(digest));
   Move(digest[0], Result[1], SizeOf(digest));
   Result := EncodeStringBase64(Result);
end; { b64_hmac_sha1 }

function hex_hmac_sha1(const key, msg: String): String;
begin
   Result := '0x' + SHA1Print(hmac_sha1(key, msg));
end; { hex_hmac_sha1 }

function hmac_sha1_test: Boolean;
begin
  Result := False;
  if hex_hmac_sha1('', '') <>
     '0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d' then
    Exit;
  if hex_hmac_sha1('key', 'The quick brown fox jumps over the lazy dog') <>
     '0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9' then
    Exit;
  if hex_hmac_sha1('The quick brown fox jumps over the lazy dog', 'key') <>
     '0xb6468830e6d2210c819986779a0f65c1993e04a6' then
    Exit;
  Result := True;
end; { hmac_sha1_test }

end.
