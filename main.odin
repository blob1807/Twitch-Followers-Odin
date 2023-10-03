package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:encoding/json"
import "core:time"
import "core:bufio"
import "core:crypto"
import "core:unicode/utf8"
import "core:net"
import "core:c/libc"
import "core:io"
import "core:bytes"
//import "vendor:raylib"

import "odin-http/client"


BASE_API_URL  : string : "https://api.twitch.tv/helix/"
FOLLOW_URL : string : BASE_API_URL + "channels/follows?first=1&broadcaster_id={0}"
USER_URL  : string : BASE_API_URL + "users?login={0}"
BASE_AUTHO_URL : string : "https://id.twitch.tv/oauth2/"
CLIENT_TOKEN_URL : string : BASE_AUTHO_URL + "token"
USER_AUTHO_URL : string : BASE_AUTHO_URL + "authorize"
VALIDATE_URL : string : BASE_AUTHO_URL + "validate"


Creds :: struct {
    client_id: string,
    client_secret: string,
    grant_type: string,
}

User_Creds :: struct {
    client_id: string,
    client_secret: string,
    grant_type: string,
    code: string,
    redirect_uri: string
}

Refresh_Creds:: struct {
    client_id: string,
    client_secret: string,
    grant_type: string,
    refresh_token: string,
}

Client_Token :: struct {
    access_token: string,
    expires_in: f64,
    token_type: string,
    date: f64,
}

User_Token :: struct {
    access_token : string,
    expires_in: f64,
    refresh_token: string,
    scope: []string,
    token_type: string,
    date: f64,
}

Irc :: struct {
    irc_token: string,
    refresh_token: string,
    client_id: string,
    nick: string,
    initial_channels: [dynamic]string,
}

Info :: struct {
    creds: Creds,
    user_creds: User_Creds,
    client_token: Client_Token,
    user_token: User_Token,
    irc: Irc,
}

Client_Autho_Res :: struct {
    access_token: string,
    expires_in: f64,
    token_type: string,
}
User_Autho_Res :: struct {
    access_token : string,
    expires_in: f64,
    refresh_token: string,
    scope: []string,
    token_type: string,
}

Error_Res :: struct {
    error: string,
    status: f64,
    message: string,
}

Get_Users_Res :: struct {
    data: [1]struct {
        id: string,
        /*login: string,
        display_name: string,
        type: string,
        broadcaster_type: string,
        description: string,
        profile_image_url: string,
        offline_image_url: string,
        view_count: f64,
        created_at: string,*/
    },
}

Get_Users_Follows_Res :: struct {
    total: f64,
    /*data: [dynamic]struct{
        from_id: string,
        from_login: string,
        from_name: string,
        to_id: string,
        to_name: string,
        followed_at: string,
    },
    pagination: struct{cursor: string}*/
}

Valid_Token_Res :: struct {
    client_id: string,
    login: string,
    scopes: []string,
    user_id: string,
    expires_in: f64,
}

Autho_Token_Type :: enum {
    Client, User, Refresh
}


get_autho_from_user :: proc (info: ^Info) -> (Success: bool) {
    Success = false
    ep := net.Endpoint{net.IP4_Loopback, 3000}
    sock, s_err := net.listen_tcp(ep)
    defer net.close(sock)
    if s_err != nil {
        fmt.println(s_err)
        return
    }
    r : [32]byte
    runes : [32]rune
    crypto.rand_bytes(r[:])
    chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for n in 0..<32 {
        runes[n] = rune(chars[int(r[n])%62])
    }
    //state := utf8.runes_to_string(runes[:])
    state := "vTaJfGFy75lpyHkf16bgR3SOeFMYmWEB"

    header := strings.builder_make()
    defer strings.builder_destroy(&header)
    strings.write_string(&header, fmt.tprintf("client_id={0}&", info.creds.client_id))
    strings.write_string(&header, "redirect_uri=http://localhost:3000&")
    strings.write_string(&header, "response_type=code&")
    strings.write_string(&header, fmt.tprint("scope=moderator%3Aread%3Afollowers&"))
    strings.write_string(&header, fmt.tprintf("state={0}", state))
    headers := strings.to_string(header)
    // libc.system(strings.clone_to_cstring(fmt.tprintf("explorer \"http://{0}/?{1}\"", net.endpoint_to_string(ep), headers)))
    // libc.system(strings.clone_to_cstring(fmt.tprintf("explorer \"{0}?{1}\"", USER_AUTHO_URL, headers)))
    // replace "explorer" with your platforms url opener
    libc.system(strings.clone_to_cstring("explorer \"http://localhost:3000/?code=17038swieks1jh1hwcdr36hekyui&scope=moderator%3Aread%3Afollowers&state=vTaJfGFy75lpyHkf16bgR3SOeFMYmWEB\"")) 
    // Also Work:
    // raylib.OpenURL("http://localhost:3000/?code=17038swieks1jh1hwcdr36hekyui&scope=moderator%3Aread%3Afollowers&state=vTaJfGFy75lpyHkf16bgR3SOeFMYmWEB")

    buf : [1024]u8
    con, epc, errc := net.accept_tcp(sock)
    if errc != nil {
        fmt.println(errc)
        return
    }
    if epc.address != ep.address {
        fmt.println("Connection from foreign address:", net.endpoint_to_string(epc))
        fmt.println("Dropping connection.")
        return
    }
    read, read_err := net.recv_tcp(con, buf[:])
    if read_err != nil {
        fmt.println(read_err)
        return
    }
    response_body := fmt.tprint("HeHe HoHo", time.now())
    sb := strings.builder_make()
    defer strings.builder_destroy(&sb)
    strings.write_string(&sb, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n")
    strings.write_string(&sb, fmt.tprintf("Content-Length: %v\r\n", len(response_body)))
    strings.write_string(&sb, "\r\n")
    strings.write_string(&sb, response_body)
    res := strings.to_string(sb)

    res_written, res_err := net.send_tcp(con, transmute([]byte)res)
    if res_err != nil {
        fmt.println(res_err, res_written, res[:res_written])
        return
    }

    raw_h := strings.split_lines(string(buf[:read]))[0]
    _,_,_, res_h := net.split_url(strings.split(raw_h, " ")[1])
    defer delete(res_h)
    if res_h["state"] != state {
        fmt.printf("Possible CSRF.\nGot: {0}\nExpected: {1}\n", res_h["state"], state)
        return
    }
    if "error" in res_h {
        fmt.println(res_h)
        return
    }
    info.user_creds.code = res_h["code"]
    info.user_creds.redirect_uri = fmt.tprintf("http://{0}", net.endpoint_to_string(ep))
    fmt.println("on get", res_h["code"], info.user_creds.code)
    return true

}

get_token :: proc(info: ^Info, t_type: Autho_Token_Type) -> (Success: bool) {
    Success = false
    // using info
    date := f64(time.now()._nsec)

    req: client.Request
    client.request_init(&req, .Post)
    defer client.request_destroy(&req)
    switch t_type{
    case .Client:
        if err := client.with_json(&req, info.creds); err != nil {
            fmt.println("JSON error:", err)
            return
        }
    case .User:
        if !get_autho_from_user(info) do return
        fmt.println("before", info.user_creds.code)
        req.headers["content-type"] = "application/x-www-form-urlencoded"
        // str := strings.builder_make()
        //strings.write_string(&str, fmt.tprintf("client_id={0}&", user_creds.client_id))
        //strings.write_string(&str, fmt.tprintf("client_secret={0}&", user_creds.client_secret))
        bytes.buffer_write_string(&req.body, fmt.aprintf("client_id=%s&", "hof5gwx0su6owfnys0yan9c87zr6t"))
        bytes.buffer_write_string(&req.body, fmt.aprintf("client_secret=%s&", "41vpdji4e9gif29md0ouet6fktd2"))
        bytes.buffer_write_string(&req.body, fmt.aprintf("grant_type=%s&", info.user_creds.grant_type))
        bytes.buffer_write_string(&req.body, fmt.aprintf("code=%s&", info.user_creds.code))
        // str, _ := strings.join([]string{"code=",info.user_creds.code, "&"}, "")
        // bytes.buffer_write_string(&req.body, str)
        bytes.buffer_write_string(&req.body, fmt.aprintf("redirect_uri={0:s}", info.user_creds.redirect_uri))
        //body := strings.to_string(str)
        //bytes.buffer_write_string(&req.body, body)
        fmt.println("after", bytes.buffer_to_string(&req.body), info.user_creds.code)
        //fmt.println(body)
    case .Refresh:
        re_creads := Refresh_Creds{
            client_id=info.creds.client_id, client_secret=info.creds.client_secret,
            grant_type = "refresh_token", refresh_token=info.user_token.refresh_token}
        if err := client.with_json(&req, re_creads); err != nil {
            fmt.println("JSON error:", err)
            return
        }
    }
        
    res, err := client.request(CLIENT_TOKEN_URL, &req)
    if err != nil {
        fmt.println("Request failed:", err)
        return
    }
    defer client.response_destroy(&res)
    if int(res.status) > 399 {
        //fmt.println("Request failed:", res.status, res.headers)
        fmt.println(bufio.scanner_text(&res._body)) 
        fmt.println(bytes.buffer_to_string(&req.body))
        return
    }

    body, allocation, berr := client.response_body(&res)
    if berr != nil {
        fmt.println("Error retrieving response body:", berr)
        return
    }
    defer client.body_destroy(body, allocation)

    ares: union{Client_Autho_Res, User_Autho_Res}
    switch t_type {
        case .Client:
            ares = Client_Autho_Res{}
        case .User, .Refresh:
            ares = User_Autho_Res{}
    }
    switch v in body {
    case string:
        if p := json.unmarshal_string(v, &ares); p != nil {
            fmt.println("Unable to parse body because of", p)
            return
        }
    case map[string]string:
        fmt.println("Invalid response body was reseived.")
        return
    case client.Body_Error:
        fmt.println("Unable to parse body because of", v)
        return
    }

    switch v in ares {
        case Client_Autho_Res:
            info.client_token.access_token = v.access_token
            info.client_token.expires_in = v.expires_in
            info.client_token.date = date
        case User_Autho_Res:
            info.user_token.access_token = v.access_token
            info.user_token.expires_in = v.expires_in
            info.user_token.refresh_token = v.refresh_token
            info.user_token.scope = v.scope
            info.user_token.date = date
    }

    out, j_err := json.marshal(info, json.Marshal_Options{pretty = true})
    if j_err != nil {
        fmt.println("Unable to parse info because of", j_err)
        fmt.println("Outputting new file contents")
        fmt.println(info)
        return
    }
    if !os.write_entire_file("info.json", out) {
            fmt.println("Unable to write to info.json.")
            fmt.println("Outputting new file contents")
            fmt.println(info)
            return
    }

    return true
}

validate_token :: proc(info: ^Info) -> (Success: bool) {
    Success = false
    date := f64(time.now()._nsec)

    req: client.Request
    client.request_init(&req)
    defer client.request_destroy(&req)
    req.headers["Authorization"] = fmt.aprint("OAuth", info.user_token.access_token)
        
    res, err := client.request(CLIENT_TOKEN_URL, &req)
    if err != nil {
        fmt.println("Validate failed:", err)
        return
    }
    defer client.response_destroy(&res)
    if int(res.status) > 399 {
        fmt.println("Validate failed:", res.status)
        return
    }
    return true

    /*body, allocation, berr := client.response_body(&res)
    if berr != nil {
        fmt.println("Error retrieving response body:", berr)
        return
    }
    defer client.body_destroy(body, allocation)

    ares := Valid_Token_Res{}
    switch v in body {
    case string:
        if p := json.unmarshal_string(v, &ares); p != nil {
            fmt.println("Unable to parse body because of", p)
            return
        }
    case map[string]string:
        fmt.println("Invalid response body was reseived.")
        return
    case client.Body_Error:
        fmt.println("Unable to parse body because of", v)
        return
    }
    return true*/

}

get_id :: proc(user: string, req: ^client.Request, info: ^Info) -> (int, bool) {
    res, err := client.request(fmt.aprintf(USER_URL, user), req)
    if err != nil {
        fmt.println("Unable to connect to twitch.")
        fmt.printf("Error: {0}", err)
        return 0, true
    }
    defer client.response_destroy(&res)

    for int(res.status) == 401 {
        fmt.println("Token invalid. Attempting to Reauthorize")
        if !get_token(info, .Client) {
            fmt.println("Unable to Reauthorize.")
            return 0, true
        }
        res, err = client.request(fmt.aprintf(USER_URL, user), req)
    }
    body, allocation, berr := client.response_body(&res)
    if berr != nil {
        fmt.println("Error retrieving response body:", berr)
        return 0, true
    }
    defer client.body_destroy(body, allocation)

    data := Get_Users_Res{}
    //if p := json.unmarshal(bufio.scanner_bytes(&res._body), &data); p != nil {
    if p := json.unmarshal_string(body.(client.Body_Plain), &data); p != nil {
        fmt.println("Unable to parse body because of", p)
        return 0, true
    }
    id, iderr := strconv.parse_int(data.data[0].id)
    if !iderr {
        fmt.printf("Unable to parse id {0} as int\n", data.data[0].id)
        return 0, true
    }

    return id, false
}

get_follows :: proc(id: int, req: ^client.Request, info: ^Info) -> (int, bool) {
    res, err := client.request(fmt.aprintf(FOLLOW_URL, id), req)
    if err != nil {
        fmt.println("Unable to connect to twitch.")
        fmt.println("Error:", err)
        return 0, false
    }
    defer client.response_destroy(&res)

    for int(res.status) == 401 {
        fmt.println("Token invalid. Attempting to Refresh/Reauthorize")
        if !get_token(info, .Refresh) {
            fmt.println("Unable to Refresh. Tring Reauthorize.")
            if !get_token(info, .User) {
                fmt.println("Unable to Reauthorize.")
                return 0, false
            }
        }
        res, err = client.request(fmt.aprintf(FOLLOW_URL, id), req)
    }
    if int(res.status) == 400 {
        fmt.printf("User ID {0} is invalid\n", id)
        return 0, false
    }

    body, allocation, berr := client.response_body(&res)
    if berr != nil {
        fmt.println("Error retrieving response body:", berr)
        return 0, false
    }
    defer client.body_destroy(body, allocation)

    data := Get_Users_Follows_Res{}
    //if p := json.unmarshal(bufio.scanner_bytes(&res._body), &data); p != nil {
    if p := json.unmarshal_string(body.(client.Body_Plain), &data); p != nil {
        fmt.println("Unable to parse body because of", p)
        return 0, false
    }
    fmt.println(res.status)
    return int(data.total), true
}

main :: proc() {
    file, read_ok := os.read_entire_file_from_filename("./_info.json")
    if !read_ok {
        fmt.println("Unable to read info.json")
        return
    }
    defer delete(file)

    info := Info{}
    if p := json.unmarshal(file, &info); p != nil {
        fmt.println("Unable to parse info.json because of", p)
        return
    }
    if !validate_token(&info) {
        if !get_token(&info, .User){
            return
        }
    }
    buf: [256]byte
    fmt.print("Username: ")

    user, err := os.read(os.stdin, buf[:])
    if err < 0 {
        fmt.println(cast(int)err)
        return
    }
    // streamer := strings.trim_space(string(buf[:user]))
    stm := "miss_court"
    for len(stm) > 24 {
        user, err = os.read(os.stdin, buf[:])
        if err < 0 {
            fmt.println(cast(int)err)
            return
        }
        stm = strings.trim_space(string(buf[:user]))
    }

    goal: int = 0
    input_ok: bool = true

    for {
        fmt.print("Goal: ")
        user, err = os.read(os.stdin, buf[:])
        if err < 0 {
            fmt.println("Unable to read input becase of Error:", cast(int)err)
            return
        }

        goal, input_ok = strconv.parse_int(strings.trim_space(string(buf[:user])))
        if input_ok do break

        fmt.println("Goal must be a whole number")
    }

    fmt.println("Streamer:", stm)
    fmt.println("Goal:", goal)

    req: client.Request
    client.request_init(&req)
    defer client.request_destroy(&req)

    req.headers["accept"] = "application/vnd.twitchtv.v5+json"
    req.headers["Client-ID"] = info.creds.client_id
    req.headers["Authorization"] = fmt.aprint("Bearer", info.client_token.access_token)
    fmt.println("Getting streamer id")
    user_id, idok := get_id(stm, &req, &info)
    fmt.println("Id got")
    if !idok do return

    cur, old, fok := 0, 0, false
    errs := 0

    for {
        cur, fok = get_follows(user_id, &req, &info)
        if !fok {
            errs += 1
            if errs == 5 {
                fmt.println("Failed to get follows to many times.")
                break
            }
        } else if cur != old {
            errs = 0
            old = cur
            fmt.println(cur)
        }
        if cur >= goal && goal != 0 {
            fmt.println("Goal reached at", time.now())
            break
        }
        time.sleep(5 * time.Second)
    }

    fmt.println("End")

}