create or replace package pkg_fernet as
  -- Util 
  function date_to_unix_timestamp(p_date date) return number;
  function unix_timestamp_to_date(p_unix_timestamp number) return date;
  function generate_key return varchar2;
  function base64url_encode_raw(p_input in raw) return varchar2;
  function base64url_encode(p_input in varchar2) return varchar2;
  function base64url_decode(p_input in varchar2) return raw;

  -- PKCS7 functions based on Matt Little's solution: http://matthewjlittle.com/2011/07/02/plsql-pkcs-7-padding
  function pkcs7_pad(p_data in raw, p_block_size in pls_integer) return raw;
  function pkcs7_trim(p_data in raw) return raw;
  
  -- Encrypt Function
  -- Important: p_key is a base64url string
  function encrypt(p_key in varchar2, p_data in varchar2) return varchar2;

  -- Decrypt Function
  -- Important: p_key is a base64url string
  function decrypt(p_key in varchar2, p_token in varchar2) return varchar2;
end pkg_fernet;
/