create or replace package body pkg_fernet as
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
end pkg_fernet;
/