create or replace package body pkg_fernet as
  function date_to_unix_timestamp(p_date date) return number is
      c_base_date      constant date   := to_date('1970-01-01', 'YYYY-MM-DD');
      c_seconds_in_day constant number := 24 * 60 * 60;
      l_utc_date       date := cast((from_tz(cast(p_date as timestamp), sessiontimezone) at time zone 'GMT') as date);
      l_unix_timestamp number;
  begin
    l_unix_timestamp := trunc((l_utc_date - c_base_date) * c_seconds_in_day);

    if (l_unix_timestamp < 0) then
      raise_application_error(-20001, 'unix_timestamp cannot be nagative');
    end if;

    return l_unix_timestamp;
  end date_to_unix_timestamp;

  function unix_timestamp_to_date(p_unix_timestamp number) return date is
      c_base_date      constant date   := to_date('1970-01-01', 'YYYY-MM-DD');
      c_seconds_in_day constant number := 24 * 60 * 60;
      l_date           date;
  begin
    if (p_unix_timestamp < 0) then
      raise_application_error(-20001, 'unix_timestamp cannot be nagative');
    end if;

    l_date := cast((from_tz(cast(
                c_base_date + (p_unix_timestamp / c_seconds_in_day)
               as timestamp), 'GMT') at time zone sessiontimezone) as date);

    return l_date;
  end unix_timestamp_to_date;

  function pkcs7_pad(p_data in raw, p_block_size in pls_integer) return raw is
    l_pad_size  pls_integer;
    l_pad_value raw(2);
  begin
    l_pad_size  := p_block_size - mod(utl_raw.length(p_data), p_block_size);
    l_pad_value := hextoraw(ltrim(to_char(l_pad_size, 'XX')));

    return utl_raw.concat(p_data, utl_raw.copies(l_pad_value, l_pad_size));
  end pkcs7_pad;

  function pkcs7_trim(p_data in raw) return raw is
    l_pad_size  pls_integer;
    l_pad_value raw(2);
  begin
    l_pad_value := utl_raw.substr(p_data, -1, 1);
    l_pad_size  := to_number(rawtohex(l_pad_value), 'XX');

    return utl_raw.substr(p_data, 1, utl_raw.length(p_data) - l_pad_size);
  end pkcs7_trim;

  function encrypt(p_key in varchar2, p_data in varchar2) return varchar2 is
    c_version        constant raw(1) := hextoraw(to_char('128', 'fmxxx'));
    --
    l_current_time   raw(8);
    l_iv             raw(16);
    --
    l_key            raw(2000);
    --l_key_base64url  varchar2(44);
    l_signing_key    raw(16);
    l_encryption_key raw(16);
    --
    l_data           raw(32760);
    l_padded_data    raw(32760);
    --
    l_ciphertext     raw(32760);
    l_basic_parts    raw(32760);
    l_hmac           raw(32);
  begin
    l_key := base64url_decode(p_key); -- Decode base64 key
    l_key := hextoraw(sha256.encrypt_raw(l_key)); -- Apply SHA256 hash to always guarantee a 256 bits key

    if utl_raw.length(l_key) != 32 then
      raise_application_error(-20001, 'Fernet key must be 32 url-safe base64-encoded bytes.');
    end if;

    --l_key_base64url  := pkg_fernet.base64url_encode_raw(l_key);
    l_signing_key    := utl_raw.substr(r => l_key, pos => 1,  len => 16);
    l_encryption_key := utl_raw.substr(r => l_key, pos => 17, len => 16);

    l_current_time := hextoraw(lpad(to_char(date_to_unix_timestamp(sysdate), 'FMXXXXXXXXXXXXXXXX'), 16, '0'));
    l_iv           := dbms_crypto.randombytes(16);

    l_data         := utl_i18n.string_to_raw(p_data, 'AL32UTF8');
    l_padded_data := pkcs7_pad(l_data, 16);

    l_ciphertext := dbms_crypto.encrypt (
                      src => l_padded_data,
                      typ => dbms_crypto.ENCRYPT_AES128 +
                             dbms_crypto.CHAIN_CBC +
                             dbms_crypto.PAD_NONE,
                      key => l_encryption_key,
                      iv  => l_iv
                    );

    l_basic_parts := utl_raw.concat (
                      c_version,
                      l_current_time,
                      l_iv,
                      l_ciphertext
                    );

    l_hmac := sha256.hmac_sha256_raw(p_text => l_basic_parts, p_key => l_signing_key);

    return base64url_encode_raw(utl_raw.concat(l_basic_parts, l_hmac));
  end encrypt;

  function decrypt(p_key in varchar2, p_token in varchar2) return varchar2 is
    invalid_token exception;
    pragma exception_init(invalid_token, -20001);
    --
    l_data   raw(32760);
    l_length number;
    --
    l_version    raw(1);
    l_time       raw(8);
    l_iv         raw(16);
    l_ciphertext raw(32760);
    l_hmac       raw(32);
    l_plaintext  raw(32760);
    --
    l_key            raw(2000);
    l_signing_key    raw(16);
    l_encryption_key raw(16);
    --
    
  begin
    if p_token is null then
      raise_application_error(-20001, 'Token cannot be null');
    end if;

    begin
      l_data := base64url_decode(p_token);
    exception when others then
      raise_application_error(-20001, 'Token is not base64url');
    end;

    l_key := base64url_decode(p_key); -- Decode base64 key
    l_key := hextoraw(sha256.encrypt_raw(l_key)); -- Apply SHA256 hash to always guarantee a 256 bits key

    if utl_raw.length(l_key) != 32 then
      raise_application_error(-20001, 'Fernet key must be 32 url-safe base64-encoded bytes.');
    end if;

    --l_key_base64url  := pkg_fernet.base64url_encode_raw(l_key);
    l_signing_key    := utl_raw.substr(r => l_key, pos => 1,  len => 16);
    l_encryption_key := utl_raw.substr(r => l_key, pos => 17, len => 16);
    -- Assing values
    l_length     := utl_raw.length(l_data);
    l_version    := utl_raw.substr(r => l_data, pos => 1,  len => 1);
    l_time       := utl_raw.substr(r => l_data, pos => 2,  len => 8);
    l_iv         := utl_raw.substr(r => l_data, pos => 10, len => 16);
    l_ciphertext := utl_raw.substr(r => l_data, pos => 26, len => l_length - 1 - 8 - 16 - 32);
    l_hmac       := utl_raw.substr(r => l_data, pos => l_length - 32 + 1, len => 32);

    -- Check version
    if rawtohex(l_version) not in ('80') then
      raise_application_error(-20001, 'Invalid Fernet version');
    end if;

    -- Check datetime
    declare
      l_dummy_date date;
    begin
      l_dummy_date := unix_timestamp_to_date(to_number(l_time, 'XXXXXXXXXXXXXXXX'));
    exception when others then
      raise_application_error(-20001, 'Invalid timestamp');
    end;

    -- Verify signature
    declare
      l_hmac_test raw(32);
    begin
      l_hmac_test := sha256.hmac_sha256_raw (
                       p_text => utl_raw.substr(l_data, 1, l_length - 32),
                       p_key  => l_signing_key
                     );
      if utl_raw.compare(l_hmac_test, l_hmac) != 0 then
        raise_application_error(-20001, 'Invalid signature');
      end if;
    end;

    begin
      l_plaintext := dbms_crypto.decrypt (
                       src => l_ciphertext,
                       typ => dbms_crypto.ENCRYPT_AES128 +
                              dbms_crypto.CHAIN_CBC +
                              dbms_crypto.PAD_NONE,
                       key => l_encryption_key,
                       iv  => l_iv
                     );
    exception when others then
      raise_application_error(-20001, 'Error when trying to decrypt the cipher');
    end;

    begin
      l_plaintext := pkcs7_trim(l_plaintext);
    exception when others then
      raise_application_error(-20001, 'Error when trying to unpad the text');
    end;

    return utl_i18n.raw_to_char(l_plaintext, 'AL32UTF8');
  --exception when others then
  --  raise_application_error(-20001, 'Invalid token');
  end decrypt;

  function base64url_encode(p_input in varchar2) return varchar2 is
  begin
    return base64url_encode_raw(utl_i18n.string_to_raw(p_input, 'AL32UTF8'));
  end base64url_encode;

  function base64url_encode_raw(p_input in raw) return varchar2 is
  begin
    return replace(replace(replace(replace(utl_i18n.raw_to_char(utl_encode.base64_encode(p_input), 'AL32UTF8'), '+', '-'), '/' , '_'), chr(13)), chr(10));
  end base64url_encode_raw;

  function base64url_decode(p_input in varchar2) return raw is
  begin
    return utl_encode.base64_decode(utl_i18n.string_to_raw(replace(replace(p_input, '-', '+'), '_', '/'), 'AL32UTF8'));
  end base64url_decode;

  function generate_key return varchar2 is
    c_key_length number := 256 / 8;
    l_key        raw(32);
  begin
    l_key := dbms_crypto.randombytes(c_key_length);

    return pkg_fernet.base64url_encode_raw(l_key);
  end generate_key;
end pkg_fernet;
/