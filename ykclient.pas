(* ykclient.pas --- Implementation of Yubikey OTP validation client library.
 *
 * Written by Tor Stenvaag <tor@agromatic.no>.
 * Copyright (c) 2013 Agromatic AS
 * All rights reserved.
 *
 * Based on ykclient.c from library ykclient-2.11 with the following
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
unit ykclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  MAX_TEMPLATES = 5;

type
  TYKClientRC = (
    // Official yubikey client API errors.
    YKCLIENT_OK = 0,
    YKCLIENT_BAD_OTP,
    YKCLIENT_REPLAYED_OTP,
    YKCLIENT_BAD_SIGNATURE,
    YKCLIENT_MISSING_PARAMETER,
    YKCLIENT_NO_SUCH_CLIENT,
    YKCLIENT_OPERATION_NOT_ALLOWED,
    YKCLIENT_BACKEND_ERROR,
    YKCLIENT_NOT_ENOUGH_ANSWERS,
    YKCLIENT_REPLAYED_REQUEST,
    // Other implementation specific errors.
    YKCLIENT_OUT_OF_MEMORY = 100,
    YKCLIENT_PARSE_ERROR,
    YKCLIENT_HMAC_ERROR,
    YKCLIENT_HEX_DECODE_ERROR,
    YKCLIENT_BASE64_DECODE_ERROR,
    YKCLIENT_BAD_SERVER_SIGNATURE,
    YKCLIENT_NOT_IMPLEMENTED,
    YKCLIENT_BAD_INPUT,
    YKCLIENT_LNET_ERROR,
    YKCLIENT_SSL_ERROR);

  EYKClientError = class(Exception)
  private
    FStatus: TYKClientRC;
  public
    constructor Create(ARet: TYKClientRC);
    property Status: TYKClientRC read FStatus;
  end;

  TYKClient = class
  protected
    FVerifySignature: Boolean;
    FClientId: Cardinal;
    FClientKey: String;
    FNonce: String;
    FNonceSupplied: Boolean;
    FCAPath: String;
    FLastUrl: String;
    FUrlTemplates: TStrings;
    FErrorMsg: String;

    procedure Error(ARet: TYKClientRC);
    function GetUrlTemplate: String;
    procedure SetUrlTemplate(const ATemplate: String); overload;
    procedure SetUrlTemplates(ATemplates: TStrings); overload;
    procedure SetClientKey(const AKey: String);
    function GetClientKeyHex: String;
    procedure SetClientKeyHex(const AKeyHex: String);
    function GetClientKeyB64: String;
    procedure SetClientKeyB64(const AKeyB64: String);
    procedure SetNonce(const ANonce: String);
    function CreateNonce: String;
  public
    constructor Create;
    destructor Destroy; override;

    function Request(const AOtp: String): TYKClientRC;
    procedure SetUrlTemplates(const ATemplates: array of String);
    class function ErrorString(ARet: TYKClientRC): String;

    property UrlTemplate: String read GetUrlTemplate write SetUrlTemplate;
    property VerifySignature: Boolean read FVerifySignature write FVerifySignature;
    property CAPath: String read FCAPath write FCAPath;
    property ClientId: Cardinal read FClientId write FClientId;
    property ClientKey: String read FClientKey write SetClientKey;
    property ClientKeyHex: String read GetClientKeyHex write SetClientKeyHex;
    property ClientKeyB64: String read GetClientKeyB64 write SetClientKeyB64;
    property Nonce: String read FNonce write SetNonce;
    property LastUrl: String read FLastUrl;
    property ErrorMsg: String read FErrorMsg;
  end;

implementation

uses
  base64, hmac_sha1, strutils,
  lnet, lhttp, lHTTPUtil, lnetSSL, URIParser, openssl;

//=============================================================
function StrToYKClientRC(const status: String): TYKClientRC;
begin
  if status = 'OK' then
     Result := YKCLIENT_OK
  else if status = 'BAD_OTP' then
     Result := YKCLIENT_BAD_OTP
  else if status = 'REPLAYED_OTP' then
     Result := YKCLIENT_REPLAYED_OTP
  else if status = 'REPLAYED_REQUEST' then
     Result := YKCLIENT_REPLAYED_REQUEST
  else if status = 'BAD_SIGNATURE' then
     Result := YKCLIENT_BAD_SIGNATURE
  else if status = 'MISSING_PARAMETER' then
     Result := YKCLIENT_MISSING_PARAMETER
  else if status = 'NO_SUCH_CLIENT' then
     Result := YKCLIENT_NO_SUCH_CLIENT
  else if status = 'OPERATION_NOT_ALLOWED' then
     Result := YKCLIENT_OPERATION_NOT_ALLOWED
  else if status = 'BACKEND_ERROR' then
     Result := YKCLIENT_BACKEND_ERROR
  else if status = 'NOT_ENOUGH_ANSWERS' then
     Result := YKCLIENT_NOT_ENOUGH_ANSWERS
  else
    Result := YKCLIENT_PARSE_ERROR;
end;

//=============================================================
// DeomposeURL - Copied from lnet/lhttputil.pp
// Added False on Decode parameter to ParseURI. If not,  
// HttpEncoding is removed and a signatures containing "+" fails.
//-------------------------------------------------------------
function DecomposeURL(const URL: string; out Host, URI: string; out Port: Word): Boolean;
var
  uri_rec: TURI;
begin
  uri_rec := ParseURI(URL, 'http', 0, False); // default to 0 so we can set SSL port
  Host := uri_rec.Host;
  URI := uri_rec.Path + uri_rec.Document;
  if uri_rec.Params <> '' then
    URI := URI + '?' + uri_rec.Params;
  Port := uri_rec.Port;

  Result := LowerCase(uri_rec.Protocol) = 'https';
  if Port = 0 then begin
    Port := 80; // default http port
    if Result then
      Port := 443; // default https/ssl port
  end;
end;

//=============================================================
type
  THttpHandlerParams = class
  protected
    FOwner: TYKClient;
    FConnected: Boolean;
    FActiveHosts: Integer;
    FOtp, FNonce: String;
    FStatus, FErrorMsg, FLastUrl: String;
    FError: TYKClientRC;
  end;

  THttpHandler = class
  private
    FParams: THttpHandlerParams;
    FURL: String;
    FHTTPClient: TLHTTPClient;
    FDone, FError, FUseSSL: Boolean;
    FBuffer: String;
    procedure Done;
    procedure Error(ARet: TYKClientRC; const AMsg: String = '');
  public
    constructor Create(AParams: THttpHandlerParams; const AURL: String);
    destructor Destroy; override; 
    procedure SendRequest;
    procedure CallAction;
    procedure ClientConnect(ASocket: TLSocket);
    procedure ClientDisconnect(ASocket: TLSocket);
    procedure ClientDoneInput(ASocket: TLHTTPClientSocket);
    procedure ClientError(const Msg: string; aSocket: TLSocket);
    function ClientInput(
      ASocket: TLHTTPClientSocket; ABuffer: pchar; ASize: Integer): Integer;
    procedure ClientProcessHeaders(ASocket: TLHTTPClientSocket);
  end;

constructor THTTPHandler.Create(AParams: THttpHandlerParams; const AURL: String);
var
  sslSession: TLSSLSession;
  port: Word;
  host, uri: String;
begin
  FParams := AParams;
  FURL := AURL;
  FUseSSL := DecomposeURL(AURL, host, uri, port);
  
  if FParams.FOwner.FCAPath <> '' then
  begin
    FUseSSL := True;
    port := 443; 
  end;
   
  FHTTPClient := TLHTTPClient.Create(nil);

  sslSession := TLSSLSession.Create(FHTTPClient);
  sslSession.SSLActive := FUseSSL;
  if (FParams.FOwner.FCAPath <> '') and 
     (SslCtxLoadVerifyLocations(sslSession.SSLContext, '', FParams.FOwner.FCAPath) <> 1) then
    FParams.FOwner.Error(YKCLIENT_SSL_ERROR);

  FHTTPClient.Session := sslSession;
  FHTTPClient.Host := host;
  FHTTPClient.Method := hmGet;
  FHTTPClient.Port := port;
  FHTTPClient.URI := uri;
  FHTTPClient.Timeout := 250;
  FHTTPClient.OnConnect := @ClientConnect;
  FHTTPClient.OnDisconnect := @ClientDisconnect;
  FHTTPClient.OnDoneInput := @ClientDoneInput;
  FHTTPClient.OnError := @ClientError;
  FHTTPClient.OnInput := @ClientInput;
  FHTTPClient.OnProcessHeaders := @ClientProcessHeaders;
end;

destructor THTTPHandler.Destroy;
begin
  FHTTPClient.Free;
  inherited;
end;       
    
procedure THTTPHandler.Done;
begin
  if FDone then
    Exit;
  Dec(FParams.FActiveHosts);
  FDone := True;
end;

procedure THTTPHandler.Error(ARet: TYKClientRC; const AMsg: String);
begin
  FParams.FError := ARet;
  FParams.FErrorMsg := AMsg;
  FParams.FConnected := True;
  FError := True;
end;

procedure THTTPHandler.SendRequest;
begin
  FHTTPClient.SendRequest;
end;

procedure THTTPHandler.CallAction;
begin
  if FDone then
    Exit;
  if FParams.FStatus <> '' then
    FHTTPClient.Disconnect;
  FHTTPClient.CallAction;
end;

procedure THTTPHandler.ClientError(const Msg: string; aSocket: TLSocket);
begin
  Error(YKCLIENT_LNET_ERROR, Msg);
end;

type
  TmyLSSLSocket = class(TLSSLSocket);

procedure THTTPHandler.ClientConnect(ASocket: TLSocket);
var
  sslSocket: TLSSLSocket;
  ret: Integer;
begin
  FParams.FConnected := True;
  Inc(FParams.FActiveHosts);
  if FUseSSL then
  begin
    sslSocket := ASocket as TLSSLSocket;
    if SslGetPeerCertificate(TmyLSSLSocket(SSLSocket).FSSL) = nil then
      Error(YKCLIENT_SSL_ERROR, 'SSL certificate missing')
    else
    begin
      ret := SSLGetVerifyResult(TmyLSSLSocket(SSLSocket).FSSL);
      if ret <> X509_V_OK then
        Error(YKCLIENT_SSL_ERROR, 
	  'Unable to verify SSL certificate. Errorcode=' + IntToStr(ret) + '. '+
	  'See http://www.openssl.org/docs/apps/verify.html.');
    end;
  end;
end;

procedure THTTPHandler.ClientDisconnect(ASocket: TLSocket);
begin
  Done;
end;

function GetParam(params: TStrings; const key: String): String;
  var
    keyEq: String;
    i, keyLen: Integer;
begin
  Result := '';
  keyEq := key + '=';
  keyLen := Length(keyEq);
  for i := 0 to params.Count - 1 do
    if Copy(params[i], 1, keyLen) = keyEq then
    begin
      Result := Copy(params[i], keyLen + 1, 128);
      Break;
    end;
end; 
  
procedure THTTPHandler.ClientDoneInput(ASocket: TLHTTPClientSocket);
var
   i : Integer;
   body: TStringList;
   h, status: String;
begin
  ASocket.Disconnect;
  if FError or (FParams.FStatus <> '') then
    Exit;
  //- Check buffer
  h := '';
  body := TStringList.Create;
  try
    body.Text := FBuffer;
    for i := body.Count - 1 downto 0 do
      if Pos('=', body[i]) = 0 then
        body.delete(i)
      else if Copy(body[i], 1, 2) = 'h=' then
      begin
        h := Copy(body[i], 3, 128);
        body.delete(i);
      end;
    if FParams.FOwner.FVerifySignature then
      if h = '' then
      begin
        Error(YKCLIENT_BAD_SERVER_SIGNATURE);
	Exit;
      end
      else
      begin
        body.Sort;
        body.Delimiter := '&';
        if h <> b64_hmac_sha1(FParams.FOwner.FClientKey, body.DelimitedText) then
	begin
	  Error(YKCLIENT_BAD_SERVER_SIGNATURE);
	  Exit;
	end;
      end;
    status := GetParam(body, 'status');
    if StrToYKClientRC(status) = YKCLIENT_PARSE_ERROR then
      Error(YKCLIENT_PARSE_ERROR);
    if (FParams.FOtp <> GetParam(body, 'otp')) or 
       (FParams.FNonce <> '') and (FParams.FNonce <> GetParam(body, 'nonce')) then
      Error(YKCLIENT_HMAC_ERROR);
    FParams.FStatus := status;
    FParams.FLastUrl := FURL;
  finally
    body.Free;
  end;
end;

function THTTPHandler.ClientInput(ASocket: TLHTTPClientSocket;
  ABuffer: pchar; ASize: Integer): Integer;
var
  len: Integer;
begin
  len := Length(FBuffer);
  SetLength(FBuffer, len + ASize);
  Move(ABuffer^, FBuffer[len + 1], ASize);
  Result := ASize;
end;

procedure THTTPHandler.ClientProcessHeaders(ASocket: TLHTTPClientSocket);
  var
    ret: Integer;
begin
  ret := HTTPStatusCodes[ASocket.ResponseStatus];
  if ret <> 200 then
    Error(YKCLIENT_LNET_ERROR, 'Wrong HTTP statuscode from server: ' + IntToStr(ret) + ' ' +
      HTTPTexts[ASocket.ResponseStatus]);
end;
    
//=============================================================
constructor EYKClientError.Create(ARet: TYKClientRC);
begin
  inherited Create(TYKClient.ErrorString(ARet));
  FStatus := ARet;
end;

//=============================================================
procedure TYKClient.Error(ARet: TYKClientRC);
begin
  raise EYKClientError.Create(ARet);
end;

constructor TYKClient.Create;
begin
  Randomize;
  FUrlTemplates := TStringList.Create;
  SetUrlTemplates([
    'http://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    'http://api2.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    'http://api3.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    'http://api4.yubico.com/wsapi/2.0/verify?id=%d&otp=%s',
    'http://api5.yubico.com/wsapi/2.0/verify?id=%d&otp=%s']);
end;

destructor TYKClient.Destroy;
begin
  FUrlTemplates.Free;
  inherited;
end;

function TYKClient.GetUrlTemplate: String;
begin
  Result := '';
  if FUrlTemplates.Count > 0 then
    Result := FUrlTemplates[0];
end;

procedure TYKClient.SetUrlTemplate(const ATemplate: String);
begin
  FUrlTemplates.Clear;
  FUrlTemplates.Add(ATemplate);
end;

procedure TYKClient.SetClientKey(const AKey: String);
begin
  FClientKey := AKey;
  FVerifySignature := AKey <> '';
end;

function TYKClient.GetClientKeyHex: String;
  const
    HEXCHAR: array[0..15] of Char = (
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
  var
    len: Integer;
    binP: PByte;
    hexP: PChar;
begin
  len := Length(FClientKey);
  SetLength(Result, 2 * len);
  binP := PByte(FClientKey);
  hexP := PChar(Result);
  while len > 0 do
  begin
    hexP^ := HEXCHAR[binP^ shr 4]; 
    Inc(hexP);
    hexP^ := HEXCHAR[binP^ and $f]; 
    Inc(hexP);
    Inc(binP);
    Dec(len);
  end;
end;

procedure TYKClient.SetClientKeyHex(const AKeyHex: String);
  var
    len: Integer;
    key: String;
begin
  key := '';
  len := Length(AKeyHex);
  if len > 0 then
  begin
    if len and 1 <> 0 then
      Error(YKCLIENT_HEX_DECODE_ERROR);
    len := len shr 1;
    SetLength(key, len);
    if HexToBin(PChar(AKeyHex), PChar(key), len) < len then
      Error(YKCLIENT_HEX_DECODE_ERROR);
  end;
  SetClientKey(key);
end;

function TYKClient.GetClientKeyB64: String;
begin
  Result := EncodeStringBase64(FClientKey);
end;

procedure TYKClient.SetClientKeyB64(const AKeyB64: String);
  var
    key: String;
begin
  key := DecodeStringBase64(AKeyB64);
  SetClientKey(key);
end;

procedure TYKClient.SetNonce(const ANonce: String);
begin
  FNonce := ANonce;
  FNonceSupplied := True;
end;

function TYKClient.CreateNonce: String;
  var
    i, len, v: Integer;
begin
  Result := '';
  len := 16 + Random(40 - 16 + 1);
  for i := 0 to len - 1 do
  begin
    v := $30 + Random(10 + 26);
    if v > $39 then
      v := v - $39 - 1 + $61;
    Result := Result + Char(v);
  end;
end;

function TYKClient.Request(const AOtp: String): TYKClientRC;
  var
    params: TStringList;
    httpParams: THTTPHandlerParams;
    httpHandlers: TList; // of THTTPHandler;
    i, p: Integer;
    h, url, queryParams, aNonce: String;
begin
  if FNonceSupplied then
    aNonce := FNonce
  else
    aNonce := CreateNonce;
  //-
  FLastUrl := '';
  FErrorMsg := '';
  //-
  httpParams := THttpHandlerParams.Create;
  httpHandlers := TList.Create;
  try
    httpParams.FOwner := Self;
    httpParams.FOtp := AOtp;
    httpParams.FNonce := aNonce;
    for i := 0 to FUrlTemplates.Count - 1 do
    begin
      url := Format(FUrlTemplates[i], [FClientId, AOtp]);
      p := Pos('?', url);
      if p = 0 then
      begin
	FErrorMsg := 'Missing "?" in template.';
 	Exit(YKCLIENT_PARSE_ERROR);
      end;
      queryParams := Copy(url, p + 1, Length(url) - p);
      params := TStringList.Create;
      params.Sorted := True;
      params.Delimiter := '&';
      params.DelimitedText := queryParams;
      if Pos('id=', queryParams) = 0 then
        params.Add('id=' + IntToStr(FClientId));
      if Pos('otp=', queryParams) = 0 then
        params.Add('otp=' + AOtp);
      if aNonce <> '' then
        params.Add('nonce=' + aNonce);
      if FClientKey <> '' then
      begin
        h := b64_hmac_sha1(FClientKey, params.DelimitedText);
        params.Add('h=' + HTTPEncode(h));
      end;
      url := Copy(url, 1, p - 1) + '?' + params.DelimitedText;
      //-
      httpHandlers.Add(THTTPHandler.Create(httpParams, url));
    end;
    //-
    for i := 0 to httpHandlers.Count - 1 do
      THTTPHandler(httpHandlers[i]).SendRequest;
    while not httpParams.FConnected or (httpParams.FActiveHosts > 0) do
      for i := 0 to httpHandlers.Count - 1 do
      	THTTPHandler(httpHandlers[i]).CallAction;
    //-
    Result := StrToYKClientRC(httpParams.FStatus);
    if Result <> YKCLIENT_PARSE_ERROR then
      FLastUrl := httpParams.FLastUrl
    else  
    begin
      Result := httpParams.FError;
      FErrorMsg := httpParams.FErrorMsg;
    end;
  finally
    for i := 0 to httpHandlers.Count - 1 do
      THttpHandler(httpHandlers[i]).Free;
    httpHandlers.Free;
    httpParams.Free;
  end;
end;

procedure TYKClient.SetUrlTemplates(const ATemplates: array of String);
  var
    i: Integer;
begin
  if Length(ATemplates) > MAX_TEMPLATES then
    Error(YKCLIENT_BAD_INPUT);	
  FUrlTemplates.Clear;
  for i := Low(ATemplates) to High(ATemplates) do
    FUrlTemplates.Add(ATemplates[i]);
end;

procedure TYKClient.SetUrlTemplates(ATemplates: TStrings);
begin
  FUrlTemplates.Clear;
  FUrlTemplates.Assign(ATemplates);
end;

class function TYKClient.ErrorString(ARet: TYKClientRC): String;
begin
  case ARet of
    YKCLIENT_OK: Result := 'Success';
    YKCLIENT_BAD_OTP: Result := 'Yubikey OTP was bad (BAD_OTP)';
    YKCLIENT_REPLAYED_OTP: Result := 'Yubikey OTP was replayed (REPLAYED_OTP)';
    YKCLIENT_BAD_SIGNATURE: Result := 'Request signature was invalid (BAD_SIGNATURE)';
    YKCLIENT_MISSING_PARAMETER: Result := 'Request was missing a parameter (MISSING_PARAMETER)';
    YKCLIENT_NO_SUCH_CLIENT: Result := 'Client identity does not exist (NO_SUCH_CLIENT)';
    YKCLIENT_OPERATION_NOT_ALLOWED: Result := 'Authorization denied (OPERATION_NOT_ALLOWED)';
    YKCLIENT_BACKEND_ERROR: Result := 'Internal server error (BACKEND_ERROR)';
    YKCLIENT_NOT_ENOUGH_ANSWERS: Result := 'Too few validation servers available (NOT_ENOUGH_ANSWERS)';
    YKCLIENT_REPLAYED_REQUEST: Result := 'Yubikey request was replayed (REPLAYED_REQUEST)';
    YKCLIENT_OUT_OF_MEMORY: Result := 'Out of memory';
    YKCLIENT_PARSE_ERROR: Result := 'Could not parse server response';
    YKCLIENT_HMAC_ERROR: Result := 'HMAC signature validation/generation error';
    YKCLIENT_HEX_DECODE_ERROR: Result := 'Error decoding hex string';
    YKCLIENT_BASE64_DECODE_ERROR: Result := 'Error decoding base64 string';
    YKCLIENT_BAD_SERVER_SIGNATURE: Result := 'Server response signature was invalid (BAD_SERVER_SIGNATURE)';
    YKCLIENT_NOT_IMPLEMENTED: Result := 'Not implemented';
    YKCLIENT_BAD_INPUT: Result := 'Passed invalid or incorrect number of parameters';
    YKCLIENT_LNET_ERROR: Result := 'Error from lNet (see extended error info)';
    YKCLIENT_SSL_ERROR: Result := 'SSL error (Unable to validate certificate)';
  else
    Result := 'Uknown error';
  end;
end;

end.
