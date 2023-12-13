Requirements:  
- odin dev-2023-10 or greater  
- odin-http
    - open ssl, libcrypto-3 & libssl-3 
- a twitch app
    - need both its ID & Secert
- a Twitch account with Mod access


Usage:  
- rename _info.json -> info.json  
- fill out client_id & client_secret in creds & user_creds before use 
- run it
- Provide the Streamer's Username  
- Provide a Goal. '0' == no goal
- It'll print the amount every time it changes  


Make a Twitch Application:
1. Goto https://dev.twitch.tv/, Login if you need to
2. Click `Your Console`
3. Click `Register Your Application`
4. Fill out the fourm
    - Give it a name
    - `http://localhost:3000` for OAuth Redirect URL
    - `Analytics Tool` for Category
5. Grab the `Client Secret` & `Client ID` **BEFORE** you close the tab/goto another page.
6. Grats you've made a Twitch App


Notes:  
Because of changes Twitch made. You need an account with at least Mod access.  
When it opens a URL to get user assume on Linx or FreeBSD it'll assume you've got `xdg-open` installed.<br> You can change this on Line:170-171