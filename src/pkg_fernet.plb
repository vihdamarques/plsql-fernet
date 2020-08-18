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

  function pkcs7_pad(p_data in blob, p_block_size in pls_integer) return blob is
    l_pad_size    pls_integer;
    l_pad_value   raw(2);
    l_pad_full    raw(1000);
    l_padded_data blob;
  begin
    l_pad_size  := p_block_size - mod(dbms_lob.getlength(p_data), p_block_size);
    l_pad_value := hextoraw(ltrim(to_char(l_pad_size, 'XX')));
    l_pad_full  := utl_raw.copies(l_pad_value, l_pad_size);
    --
    dbms_lob.createTemporary(l_padded_data, false, dbms_lob.call);
    dbms_lob.copy(l_padded_data, p_data, dbms_lob.getlength(p_data));
    dbms_lob.writeAppend(l_padded_data, utl_raw.length(l_pad_full), l_pad_full);
    --
    return l_padded_data;
  end pkcs7_pad;

  function pkcs7_trim(p_data in blob) return blob is
    l_pad_size     pls_integer;
    l_pad_value    raw(2);
    l_trimmed_data blob;
  begin
    l_pad_value := dbms_lob.substr(p_data, 1, dbms_lob.getlength(p_data));
    l_pad_size  := to_number(rawtohex(l_pad_value), 'XX');
    --
    dbms_lob.createTemporary(l_trimmed_data, false, dbms_lob.call);
    dbms_lob.copy(l_trimmed_data, p_data, dbms_lob.getlength(p_data) - l_pad_size);
    --
    return l_trimmed_data;
    --dbms_lob.freeTemporary(l_temp_data);
  end pkcs7_trim;

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

  function blob2base64url(p_blob in blob, p_encoding in varchar2 default 'AL32UTF8') return clob is
    l_clob           clob;
    l_result         clob;
    l_offset         integer := 1;
    l_buffer_size    integer := (56 / 4) * 3;
    l_buffer_raw     raw(56);
    l_buffer_varchar varchar2(56);
  begin
    if (p_blob is null) then
      return null;
    end if;

    dbms_lob.createtemporary(l_clob, true);

    for i in 1 .. ceil(dbms_lob.getlength(p_blob) / l_buffer_size) loop
      dbms_lob.read(p_blob, l_buffer_size, l_offset, l_buffer_raw);
      l_buffer_varchar := replace(replace(replace(replace(
                            utl_i18n.raw_to_char (
                              utl_encode.base64_encode(l_buffer_raw),
                              p_encoding
                            ),
                            '+', '-'), '/' , '_'), chr(13)), chr(10)
                          );
      dbms_lob.writeappend(l_clob, length(l_buffer_varchar), l_buffer_varchar);
      l_offset := l_offset + l_buffer_size;
    end loop;

    l_result := l_clob;
    dbms_lob.freetemporary(l_clob);

    return l_result;
  end blob2base64url;

  function base64url2blob(p_clob in clob, p_encoding in varchar2 default 'AL32UTF8') return blob is
    l_result         blob;
    l_blob           blob;
    l_offset         integer := 1;
    l_buffer_size    integer := 56;
    l_buffer_raw     raw(56);
    l_buffer_varchar varchar2(56);
  begin
    if (p_clob is null) then
      return null;
    end if;

    dbms_lob.createtemporary(l_blob, true);

    for i in 1..ceil(dbms_lob.getlength(p_clob) / l_buffer_size) loop
      dbms_lob.read(p_clob, l_buffer_size, l_offset, l_buffer_varchar);
      l_buffer_raw := utl_encode.base64_decode (
                        utl_i18n.string_to_raw (
                          replace(replace(l_buffer_varchar, '-', '+'), '_', '/'),
                          p_encoding
                        )
                      );
      dbms_lob.writeappend(l_blob, utl_raw.length(l_buffer_raw), l_buffer_raw);
      l_offset := l_offset + l_buffer_size;
    end loop;

    l_result := l_blob;
    dbms_lob.freetemporary(l_blob);

    return l_result;
  end base64url2blob;

  function base64url_encode(p_input in raw) return varchar2 is
  begin
    return replace(replace(replace(replace(utl_i18n.raw_to_char(utl_encode.base64_encode(p_input), 'AL32UTF8'), '+', '-'), '/' , '_'), chr(13)), chr(10));
  end base64url_encode;

  function base64url_decode(p_input in varchar2) return raw is
  begin
    return utl_encode.base64_decode(utl_i18n.string_to_raw(replace(replace(p_input, '-', '+'), '_', '/'), 'AL32UTF8'));
  end base64url_decode;

  function is_base64url(p_string in varchar2) return boolean is
  begin
    if p_string is null then
      return false;
    end if;

    if mod(length(p_string), 4) != 0 then
      return false;
    end if;

    if not regexp_like(replace(replace(p_string, '-', '+'), '_', '/'), '^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$') then
      return false;
    end if;

    if not regexp_like(p_string, '^([A-Za-z0-9]|\-|\_|=)+$') then
      return false;
    end if;

    return true;
  end is_base64url;

  function is_base64url(p_clob in clob) return boolean is
    l_buffer_size pls_integer := 32764; -- max 4-divisible # bellow 32767
    l_chunk varchar2(32764);
  begin
    for i in 1 .. ceil(nvl(dbms_lob.getlength(p_clob), 0) / l_buffer_size) loop
      l_chunk := dbms_lob.substr(p_clob, l_buffer_size, ((i - 1) * l_buffer_size) + 1);
      if not is_base64url(l_chunk) then
        return false;
      end if;
    end loop;

    return true;
  end is_base64url;

  function hmac_sha256(p_input in blob, p_key in raw) return raw is
    l_hash raw(32);
  begin
    l_hash := dbms_crypto.mac(
      src => p_input,
      typ => dbms_crypto.HMAC_SH256,
      key => p_key
    );
    --
    return l_hash;
  end hmac_sha256;

  function encrypt(p_key in varchar2, p_data in clob, p_encoding in varchar2 default 'AL32UTF8') return clob is
    c_version        constant raw(1) := hextoraw(to_char('128', 'fmxxx'));
    --
    l_current_time   raw(8);
    l_iv             raw(16);
    --
    l_key            raw(2000);
    l_signing_key    raw(16);
    l_encryption_key raw(16);
    --
    l_data           blob;
    l_padded_data    blob;
    --
    l_ciphertext     blob;
    l_basic_parts    blob;
    l_hmac           raw(32);
    --
    l_clob_offset  integer := 1;
    l_blob_offset  integer := 1;
    l_amount       integer := dbms_lob.lobmaxsize;
    l_lang_context number  := dbms_lob.default_lang_ctx;
    l_warning      integer;
  begin
    begin
      if is_base64url(p_key) then
        l_key := base64url_decode(p_key);

        if utl_raw.length(l_key) != 32 then
          raise dbms_crypto.KeyBadSize;
        end if;
      else
        raise dbms_crypto.KeyBadSize;
      end if;
    exception when others then
      raise_application_error(-20001, 'Fernet key must be 32 url-safe base64-encoded bytes.');
    end;
    --
    l_signing_key    := utl_raw.substr(r => l_key, pos => 1,  len => 16);
    l_encryption_key := utl_raw.substr(r => l_key, pos => 17, len => 16);
    --
    l_current_time := hextoraw(lpad(to_char(date_to_unix_timestamp(sysdate), 'FMXXXXXXXXXXXXXXXX'), 16, '0'));
    l_iv           := dbms_crypto.randombytes(16);
    --
    dbms_lob.createTemporary(l_data, true, dbms_lob.call);
    dbms_lob.createTemporary(l_ciphertext, true, dbms_lob.call);
    --
    dbms_lob.convertToBlob (
      l_data,
      p_data,
      l_amount,
      l_blob_offset,
      l_clob_offset,
      nls_charset_id(p_encoding),
      l_lang_context,
      l_warning
    );
    l_padded_data := pkcs7_pad(l_data, 16);
    --
    dbms_crypto.encrypt (
      dst => l_ciphertext,
      src => l_padded_data,
      typ => dbms_crypto.ENCRYPT_AES128 +
             dbms_crypto.CHAIN_CBC +
             dbms_crypto.PAD_NONE,
      key => l_encryption_key,
      iv  => l_iv
    );
    dbms_lob.createTemporary(l_basic_parts, false, dbms_lob.call);
    dbms_lob.writeAppend(l_basic_parts, utl_raw.length(c_version), c_version);
    dbms_lob.writeAppend(l_basic_parts, utl_raw.length(l_current_time), l_current_time);
    dbms_lob.writeAppend(l_basic_parts, utl_raw.length(l_iv), l_iv);
    dbms_lob.append(l_basic_parts, l_ciphertext);
    --
    l_hmac := hmac_sha256(p_input => l_basic_parts, p_key => l_signing_key);
    --
    dbms_lob.writeAppend(l_basic_parts, utl_raw.length(l_hmac), l_hmac);
    --
    dbms_lob.freeTemporary(l_data);
    dbms_lob.freeTemporary(l_ciphertext);
    --
    return blob2base64url(l_basic_parts);
  end encrypt;

  function decrypt(p_key in varchar2, p_token in clob, p_encoding in varchar2 default 'AL32UTF8') return clob is
    l_data   blob;
    l_length number;
    --
    l_version     raw(1);
    l_time        raw(8);
    l_iv          raw(16);
    l_ciphertext  blob;
    l_hmac        raw(32);
    l_plaintext   blob;
    l_return_text clob;
    --
    l_key            raw(2000);
    l_signing_key    raw(16);
    l_encryption_key raw(16);
    --
    l_clob_offset  integer := 1;
    l_blob_offset  integer := 1;
    l_amount       integer := dbms_lob.lobmaxsize;
    l_lang_context number  := dbms_lob.default_lang_ctx;
    l_warning      integer;
  begin
    if is_base64url(p_token) then
      l_data := base64url2blob(p_token);
    else
      raise_application_error(-20001, 'Token must be base64url encoded');
    end if;

    begin
      if is_base64url(p_key) then
        l_key := base64url_decode(p_key);

        if utl_raw.length(l_key) != 32 then
          raise dbms_crypto.KeyBadSize;
        end if;
      else
        raise dbms_crypto.KeyBadSize;
      end if;
    exception when others then
      raise_application_error(-20001, 'Fernet key must be 32 url-safe base64-encoded bytes.');
    end;

    l_signing_key    := utl_raw.substr(r => l_key, pos => 1,  len => 16);
    l_encryption_key := utl_raw.substr(r => l_key, pos => 17, len => 16);

    -- Assing values
    l_length     := nvl(dbms_lob.getlength(l_data), 0);
    l_version    := dbms_lob.substr(l_data, 1, 1);
    l_time       := dbms_lob.substr(l_data, 8, 2);
    l_iv         := dbms_lob.substr(l_data, 16, 10);
    --
    dbms_lob.createTemporary(l_ciphertext, true);
    --
    dbms_lob.copy(l_ciphertext, l_data, l_length - 1 - 8 - 16 - 32 , 1, 26);
    --
    l_hmac       := dbms_lob.substr(l_data, 32, l_length - 32 + 1);

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
      l_blob_test blob;
    begin
      dbms_lob.createTemporary(l_blob_test, true);
      dbms_lob.copy(l_blob_test, l_data, l_length - 32, 1);
      --
      l_hmac_test := hmac_sha256(p_input => l_blob_test, p_key => l_signing_key);
      if utl_raw.compare(l_hmac_test, l_hmac) != 0 then
        raise_application_error(-20001, 'Invalid signature');
      end if;
      dbms_lob.freeTemporary(l_blob_test);
    end;

    dbms_lob.createTemporary(l_plaintext, true);
    begin
      dbms_crypto.decrypt (
        dst => l_plaintext,
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

    dbms_lob.createTemporary(l_return_text, true, dbms_lob.call);
    dbms_lob.convertToClob (
      l_return_text,
      l_plaintext,
      l_amount,
      l_clob_offset,
      l_blob_offset,
      nls_charset_id(p_encoding),
      l_lang_context,
      l_warning
    );
    dbms_lob.freeTemporary(l_plaintext);
    dbms_lob.freeTemporary(l_ciphertext);

    return l_return_text;
  end decrypt;

  function generate_key return varchar2 is
    c_key_length number := 256 / 8;
    l_key        raw(32);
  begin
    l_key := dbms_crypto.randombytes(c_key_length);
    --
    return base64url_encode(l_key);
  end generate_key;

  function encode_key(p_key in varchar2) return varchar2 is
    l_key raw(32760);
  begin
    l_key := utl_i18n.string_to_raw(p_key, 'AL32UTF8');
    --
    l_key := dbms_crypto.hash(
      src => p_key,
      typ => dbms_crypto.HASH_SH256
    );
    --
    return base64url_encode(l_key);
  end encode_key;
end pkg_fernet;
/