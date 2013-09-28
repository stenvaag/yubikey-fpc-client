(* tool.pas --- Command line interface to libykclient.
 *
 * Written by Tor Stenvaag <tor@agromatic.no>.
 * Copyright (c) 2013 Agromatic AS
 * All rights reserved.
 *
 * Based on tool.c from library ykclient-2.11 with the following
 * copyright:
 *
 * Copyright (c) 2006-2013 Yubico AB
 * Copyright (c) 2012 Secure Mission Solutions
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
program tool;

{$mode objfpc}{$H+}

uses
  getopts, sysutils, ykclient;

const
   VERSION = 'ykclient (fpc) 1.0';

  EXIT_SUCCESS = 0;
  EXIT_FAILURE = 1;

  LONG_OPTIONS: array[0..6] of TOption = (
    (Name:'url'; Has_arg:1; Flag:nil; Value:'u'),
    (Name:'ca'; Has_arg:1; Flag:nil; Value:'c'),
    (Name:'apikey'; Has_arg:1; Flag:nil; Value:'a'),
    (Name:'debug'; Has_arg:0; Flag:nil; Value:'d'),
    (Name:'help'; Has_arg:0; Flag:nil; Value:'h'),
    (Name:'version'; Has_arg:0; Flag:nil; Value:'V'),
    (Name:''; Has_arg:0; Flag:nil; Value:#0));

  USAGE = 
'Usage:ykclient [OPTION]... CLIENTID YUBIKEYOTP'#10+
'Validate the YUBIKEYOTP one-time-password against the YubiCloud'#10+
'   using CLIENTID as the client identifier.'#10+
''#10+
'Mandatory arguments to long options are mandatory for short options too.'#10+
'    --help         Display this help screen'#10+
'    --version      Display version information'#10+
''#10+
'    --debug        Print debugging information'#10+
'    --url URL      Validation service URL, for example,'#10+
'       "http://api.yubico.com/wsapi/verify?id=%d&otp=%s"'#10+
'    --ca CADIR     Path to directory containing Certificate Authoritity,'#10+
'       e.g., "/usr/local/etc/CERTS"'#10+
'    --apikey Key   API key for HMAC validation of request/response'#10+
''#10+
'Exit status is 0 on success, 1 if there is a hard failure, 2 if the'#10+
'OTP was replayed, 3 for other soft OTP-related failures.'#10+
''#10+
'Report bugs at <https://github.com/stenvaag/yubikey-fpc-client>.'#10;

var
  apiKey: String;
  debug: Boolean;
  url: String;
  ca: String;
  clientId: Integer;
  otp: String;

procedure ParseArgs;
  var
    paramind: Integer;
    c: Char;
begin
  apiKey := '';
  debug := False;
  url := '';
  ca := '';

  paramind := 0;
  while True do
  begin
    c := GetLongOpts('', @LONG_OPTIONS[0], paramind);
    case c of
      EndOfOptions: Break;
      'a': begin
        if Length(OptArg) < 16 then
	begin
	  WriteLn(StdErr, 'error: API key must be at least 16 characters'); 
	  Halt(EXIT_FAILURE);
	end;
	apiKey := OptArg;
      end;
      'd': debug := True;
      'u': begin
        if (Pos('http://', OptArg) <> 1) and 
	   (Pos('https://', OptArg) <> 1) then
	begin
	  WriteLn(StdErr, 'error: validation url must be http or https');
	  Halt(EXIT_FAILURE);
	end;
	url := OptArg;
      end;
      'c': begin
        if Length(OptArg) = 0 then
	begin
	  WriteLn(StdErr, 'error: must give a valid directory containing CAs');
	  Halt(EXIT_FAILURE);
	end;
	ca := OptArg;
      end;
      'h': begin
        Write(USAGE);
	Halt(EXIT_SUCCESS);
      end;	
      'V': begin
        WriteLn(VERSION);
	Halt(EXIT_SUCCESS);
      end;
    end;
  end;

  if ParamCount - OptInd + 1 <> 2 then
  begin
    Write(USAGE);
    Halt(EXIT_SUCCESS);
  end;

  clientId := StrToInt(ParamStr(OptInd)); Inc(OptInd);
  if clientId <= 0 then
  begin
    WriteLn(StdErr, 'error: client identity must be a non-zero integer.');
    Halt(EXIT_FAILURE);
  end;

  otp := ParamStr(OptInd); Inc(OptInd);
  if Length(otp) < 32 then
  begin
    WriteLn(StdErr, 'error: modhex encoded token must be at least 32 characters');
    Halt(EXIT_FAILURE);
  end;
end;

var
  ykc: TYKClient;
  ret: TYKClientRC;

begin 
  ParseArgs;
  ykc := TYKClient.Create;
  try
    if ca <> '' then
      ykc.CAPath := ca;
    if apiKey <> '' then
      ykc.ClientKeyB64 := apiKey;
    ykc.ClientId := clientId;
    if url <> '' then
      ykc.UrlTemplate := url;
    if debug then
    begin
      WriteLn(StdErr, 'Input:');
      if url <> '' then
      	WriteLn(StdErr, '  validation URL: ', url);
      if ca <> '' then
	WriteLn(StdErr, '  CA Path: ', ca);
      WriteLn(StdErr, '  client id: ', clientId);
      WriteLn(StdErr, '  token: ', otp);
      if apiKey <> '' then
	WriteLn(StdErr, '  api key: ', apiKey);
    end;

    ret := ykc.Request(otp);

    if debug then
      WriteLn('Verification output (', Ord(ret), '): ', TYKClient.ErrorString(ret));

    if ret = YKCLIENT_REPLAYED_OTP then
      Halt(2)
    else if ret <> YKCLIENT_OK then
    begin
      if ret = YKCLIENT_LNET_ERROR then
        WriteLn('Extended error info: ' + ykc.ErrorMsg);
      Halt(3);
    end;

    Halt(EXIT_SUCCESS);
  finally
    ykc.Free;
  end;
end.
