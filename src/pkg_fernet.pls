create or replace package pkg_fernet as
  -- PKCS7 functions based on Matt Little's solution: http://matthewjlittle.com/2011/07/02/plsql-pkcs-7-padding
  function pkcs7_pad(p_data in raw, p_block_size in pls_integer) return raw;
  function pkcs7_trim(p_data in raw) return raw;
end pkg_fernet;
/