# plsql-fernet
PL/SQL implementation of the Fernet symetric encryption method

## Example
    declare
      l_key       varchar2(44);
      l_token     varchar2(32000);
      l_plaintext varchar2(32000);
    begin
      -- You can generate a random strong key (recommended)
      l_key := pkg_fernet.generate_key;
      -- or you can use any custom key you want, however you must encode it to enforce the compatibility with the algorithm
      --l_key := pkg_fernet.encode_key('anykey123##');
      dbms_output.put_line('key: ' || l_key);

      l_token := pkg_fernet.encrypt(l_key, 'Crypto Test');
      dbms_output.put_line('Token: ' || l_token);

      l_plaintext := pkg_fernet.decrypt(l_key, l_token);
      dbms_output.put_line('Plain text: ' || l_plaintext);
    end;
    /

## Compatibility
This package can be used on Oracle 10g+ database in a DBMS_CRYPTO execute granted schema.
If your schema doesn't have the right permissions, you can grant it using the following command as sysdba:

    grant execute on sys.dbms_crypto to SCHEMA;

## Notes
* If you are using Oracle 12c+ you can get rid of the sha256 package and use the standard DBMS_CRYPTO SHA256 support.
