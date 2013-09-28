(* selftest.pas --- Self-tests for Yubico client library.
 *
 * Written by Tor Stenvaag <tor@agromatic.no>
 * Copyright (c) 2013 Agromatic AS
 * All rights reserved.
 *
 * Based on selftest.c from library ykclient-2.11 with the following
 * copyright:
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006-2013 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *)
program selftest;

{$mode objfpc}{$H+}

uses
  sysutils,
  hmac_sha1,
  base64,
  ykclient;

procedure Assert(ok: Boolean);
begin
  if ok then
    Exit;
  WriteLn(stderr, 'Assertion failed');
  Halt;
end;

procedure TEST(const xX: String);
begin
  WriteLn(xX);
end;

var
  ykc: TYKClient;

procedure DoRequest(const msg: String; expect: TYKClientRC);
var
  ret: TYKClientRC;
begin
  TEST(msg);
{$ifndef TEST_WITHOUT_INTERNET}
  ret := ykc.Request('ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj');
  WriteLn('TYKClient.Request (', ret, '): ', TYKClient.ErrorString(ret));
  WriteLn('used url: ', ykc.LastUrl);
  Assert(ret = expect);
{$else}
  WriteLn('Test SKIPPED');
{$endif}
end;

procedure test_v1_validation(client_id: Integer; const client_b64key: String);
begin
  try
    ykc := TYKClient.Create;
    try
      ykc.UrlTemplate := 'http://api.yubico.com/wsapi/verify?id=%d&otp=%s';

      ykc.ClientId := client_id;
      ykc.VerifySignature := False;
      DoRequest('null client_id, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      // Test signed request. When signing requests to a v1 service, we must clear the nonce first.
      ykc.ClientId := client_id;
      ykc.ClientKeyB64 := client_b64key;
      ykc.Nonce := '';
      DoRequest('signed request, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);
    finally
      ykc.Free;
    end;
  except
    on e: Exception do
      WriteLn(e.Message);
  end;
end;

procedure test_base64;
var
  b64dig, buf: String;
begin
  TEST('test base64 encoding');
  b64dig := EncodeStringBase64('foo');
  Writeln('b64 encode: ', b64dig, ', expected: Zm9v');
  Assert(b64dig = 'Zm9v');

  TEST('test base64 decoding');
  buf := DecodeStringBase64('YmxhaG9uZ2E=');
  WriteLn('b64 decode: ', buf, ', expexted: blahonga');
  Assert(buf = 'blahonga');
end;

// test cases for HMAC-SHA1 from rcs 2202
procedure test_hmac;
var
  res: String;
  text1, text2, text3, text4, text5, text6, text7: String;
  key1, key2, key3, key4, key5, key6 , key7: String;
  expected1, expected2, expected3, expected4, expected5, expected6, expected7: String;
begin
  text1 := 'Hi There';
  SetLength(key1, 20); FillChar(key1[1], 20, $0b);  
  expected1 := '0xb617318655057264e28bc0b6fb378c8ef146be00';

  text2 := 'what do ya want for nothing?';
  key2 := 'Jefe';
  expected2 := '0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79';

  SetLength(text3, 50); FillChar(text3[1], 50, $dd);
  SetLength(key3, 20); FillChar(key3[1], 20, $aa);
  expected3 := '0x125d7342b9ac11cd91a39af48aa17b4f63f175d3';

  SetLength(text4, 50); FillChar(text4[1], 50, $cd);
  key4 := #$01#$02#$03#$04#$05#$06#$07#$08#$09#$0a#$0b#$0c#$0d#$0e#$0f#$10#$11#$12#$13#$14#$15#$16#$17#$18#$19;
  expected4 := '0x4c9007f4026250c6bc8414f9bf50c86c2d7235da';

  text5 := 'Test With Truncation';
  SetLength(key5, 20); FillChar(key5[1], 20, $0c);  
  expected5 := '0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04';

  text6 := 'Test Using Larger Than Block-Size Key - Hash Key First';
  SetLength(key6, 80); FillChar(key6[1], 80, $aa);  
  expected6 := '0xaa4ae5e15272d00e95705637ce8a3b55ed402112';

  text7 := 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data';
  SetLength(key7, 80); FillChar(key7[1], 80, $aa);  
  expected7 := '0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91';

  TEST('HMAC-SHA1 case 1');
  res := hex_hmac_sha1(key1, text1);
  assert(res = expected1);

  TEST('HMAC-SHA1 case 2');
  res := hex_hmac_sha1(key2, text2);
  assert(res = expected2);

  TEST('HMAC-SHA1 case 3');
  res := hex_hmac_sha1(key3, text3);
  assert(res = expected3);

  TEST('HMAC-SHA1 case 4');
  res := hex_hmac_sha1(key4, text4);
  assert(res = expected4);

  TEST('HMAC-SHA1 case 5');
  res := hex_hmac_sha1(key5, text5);
  assert(res = expected5);

  TEST('HMAC-SHA1 case 6');
  res := hex_hmac_sha1(key6, text6);
  assert(res = expected6);

  TEST('HMAC-SHA1 case 7');
  res := hex_hmac_sha1(key7, text7);
  assert(res = expected7);

  TEST('hmac_sha1.pas internal test');
  assert(hmac_sha1.hmac_sha1_test());
end;

var
  client_id: Integer;
  client_key, client_hexkey, client_b64key: String;
  ret: TYKClientRC;

begin
   try
    client_id := 1851;
    client_key := #$a0#$15#$5b#$36#$de#$c8#$65#$e8#$59#$19#$1f#$7d#$ae#$fa#$bc#$77#$a4#$59#$d4#$33;
    client_hexkey := 'a0155b36dec865e859191f7daefabc77a459d433';
    client_b64key := 'oBVbNt7IZehZGR99rvq8d6RZ1DM=';

    ykc := TYKClient.Create;
    try
      ykc.ClientId := client_id;
      ykc.VerifySignature := False;
      DoRequest('null client_id, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      ykc.ClientKey := client_key;
      ykc.VerifySignature := False;
      DoRequest('client_id set(20), correct client_key, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      ykc.ClientKey := Copy(client_key, 1, 10);
      ykc.VerifySignature := False;
      DoRequest('wrong client_id set(10), correct client_key, expect BAD_SIGNATURE', YKCLIENT_BAD_SIGNATURE);

      TEST('invalid client_id set(a), correct client_key, expect HEX_DECODE_ERROR');
      ret := YKCLIENT_OK;
      try
        ykc.ClientKeyHex := 'a';
      except
        on e: EYKClientError do
	   ret := e.Status;
      end;
      WriteLn('TYKClient.ClientKeyHex(', ret, '): ', TYKClient.ErrorString(ret));
      Assert(ret = YKCLIENT_HEX_DECODE_ERROR);

      TEST('invalid client_id set(xx), correct client_key, expect HEX_DECODE_ERROR');
      ret := YKCLIENT_OK;
      try
        ykc.ClientKeyHex := 'xx';
      except
        on e: EYKClientError do
	   ret := e.Status;
      end;
      WriteLn('TYKClient.ClientKeyHex(', ret, '): ', TYKClient.ErrorString(ret));
      Assert(ret = YKCLIENT_HEX_DECODE_ERROR);

      TEST('hex client_id set, correct client_key, expect OK');
      ret := YKCLIENT_OK;
      try
        ykc.ClientKeyHex := client_hexkey;
      except
        on e: EYKClientError do
	   ret := e.Status;
      end;
      WriteLn('TYKClient.ClientKeyHex(', ret, '): ', TYKClient.ErrorString(ret));
      Assert(ret = YKCLIENT_OK);

      DoRequest('validation request, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      TEST('set deadbeef client_id, expect OK');
      ret := YKCLIENT_OK;
      try
        ykc.ClientKeyHex := 'deadbeef';
      except
        on e: EYKClientError do
	   ret := e.Status;
      end;
      WriteLn('TYKClient.ClientKeyHex(', ret, '): ', TYKClient.ErrorString(ret));
      Assert(ret = YKCLIENT_OK);

      ykc.VerifySignature := False;
      DoRequest('validation request, expect BAD_SIGNATURE', YKCLIENT_BAD_SIGNATURE);

      TEST('b64 set deadbeef client_id, expect OK');
      ret := YKCLIENT_OK;
      try
        ykc.ClientKeyB64 := 'deadbeef';
      except
        on e: EYKClientError do
	   ret := e.Status;
      end;
      WriteLn('TYKClient.ClientKeyB64(', ret, '): ', TYKClient.ErrorString(ret));
      Assert(ret = YKCLIENT_OK);

      (* When the server dislikes our signature, it will sign the response with a
         NULL key, so the API call will fail with BAD_SERVER_SIGNATURE even though
         the server returned status=BAD_SIGNATURE.
      *)
      DoRequest('validation request, expect BAD_SERVER_SIGNATURE', YKCLIENT_BAD_SERVER_SIGNATURE);

      (* Now, disable our checking of the servers signature to get the error
         the server returned (server will use 00000 as key when signing this
         error response).
      *)
      ykc.VerifySignature := False;
      DoRequest('validation request, expect BAD_SIGNATURE', YKCLIENT_BAD_SIGNATURE);

      TEST('b64 set client_b64key, expect OK');
      ret := YKCLIENT_OK;
      try
        ykc.ClientKeyB64 := client_b64key;
      except
        on e: EYKClientError do
	   ret := e.Status;
      end;
      WriteLn('TYKClient.ClientKeyB64(', ret, '): ', TYKClient.ErrorString(ret));
      Assert(ret = YKCLIENT_OK);

      DoRequest('validation request, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      TEST('set WS 2.0 URL template');
      // Set one URL and run tests with that.
      ykc.UrlTemplate := 'http://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s';

      DoRequest('validation request, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      ykc.VerifySignature := True;
      ykc.ClientId := client_id;
      ykc.ClientKey := client_key;
      DoRequest('validation request with valid signature, expect REPLAYED_OTP', YKCLIENT_REPLAYED_OTP);

      // Check a genuine signature with a truncated key.
      ykc.ClientKey := Copy(client_key, 1, 10);
      DoRequest('validation request with bad key, expect YKCLIENT_BAD_SERVER_SIGNATURE', YKCLIENT_BAD_SERVER_SIGNATURE);

      ykc.SetUrlTemplates([
	'http://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
	'http://api2.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    	'http://api3.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    	'http://api4.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    	'http://api5.yubico.com/wsapi/2.0/verify?id=%d&otp=%s']);
      ykc.ClientKey := client_key;
      DoRequest('Set and use several V2.0 URLs', YKCLIENT_REPLAYED_OTP);
    finally
      ykc.Free;
    end;

    TEST('TYKClient.ErrorString YKCLIENT_OK');
    WriteLn('TYKClient.ErrorString(YKCLIENT_OK): ', TYKClient.ErrorString(YKCLIENT_OK));
    Assert(TYKClient.ErrorString(YKCLIENT_OK) = 'Success');

    TEST('TYKClient.ErrorString YKCLIENT_BAD_OTP');
    WriteLn('TYKClient.ErrorString(YKCLIENT_BAD_OTP): ', TYKClient.ErrorString(YKCLIENT_BAD_OTP));
    Assert(TYKClient.ErrorString(YKCLIENT_BAD_OTP) = 'Yubikey OTP was bad (BAD_OTP)');
  except
    on e: Exception do
      WriteLn(e.Message);
  end;

  test_v1_validation(client_id, client_b64key);

  test_base64;

  test_hmac;

  WriteLn('All tests passed');

  Exit;
end.
