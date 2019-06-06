# plsql-fernet
PL/SQL implementation of the Fernet symetric encryption method

## Compatibility
This code can be used in Oracle 10g+ database, in a DBMS_CRYPTO execute granted schema.

## Example
    declare
      l_key       varchar2(44);
      l_cipher    varchar2(32000);
      l_plaintext varchar2(32000);
    begin
      l_key := pkg_fernet.generate_key;
      dbms_output.put_line('key: ' || l_key);

      l_cipher := pkg_fernet.encrypt(l_key, 'Crypto Test');
      dbms_output.put_line('Cipher: ' || l_cipher);

      l_plaintext := pkg_fernet.decrypt(l_key, l_cipher);
      dbms_output.put_line('Plain text: ' || l_plaintext);
    end;
    /

## Notes
* If you are using Oracle 12c+ you can get rid of the sha256 package and use the standard DBMS_CRYPTO SHA256 support.