create or replace package pkg_fernet as
  -- Key Tools
  -- Generate strong random key
  function generate_key return varchar2;
  -- Use this function when using plain text human-readable keys
  function encode_key(p_key in varchar2) return varchar2;

  -- PKCS7 functions based on Matt Little's solution: http://matthewjlittle.com/2011/07/02/plsql-pkcs-7-padding
  function pkcs7_pad(p_data in raw, p_block_size in pls_integer) return raw;
  function pkcs7_trim(p_data in raw) return raw;

  -- Encrypt Function
  -- Important: p_key is a base64url string
  function encrypt(p_key in varchar2, p_data in varchar2) return varchar2;

  -- Decrypt Function
  -- Important: p_key and p_token are base64url strings
  function decrypt(p_key in varchar2, p_token in varchar2) return varchar2;
end pkg_fernet;
/