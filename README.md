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

From now on, this package can only be used on Oracle 12c+ because of the SH256 support on DBMS_CRYPTO. If you need to run it on 10g or 11g you can refer to [this repository](https://github.com/CruiserX/sha256_plsql) so you can implement your own version.

It's necessary to have execute grant on DBMS_CRYPTO package. If your schema doesn't have the right permissions, you can grant using the following command as sysdba:

    grant execute on sys.dbms_crypto to SCHEMA;
