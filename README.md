Requierments:  
- odin dev-2023-10 or greater  
- odin-http
    - open ssl, libcrypto-3 & libssl-3  
- Currently only works with Windows.
    - replace the libc.system call @line:173 in get_autho_from_user<br>
    with your platforms way of opening URLs
    - or use raylib.OpenUrl

rename _info.json -> info.  
fill out client_id & client_secret in creds & user_creds befor use  