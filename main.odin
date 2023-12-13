package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:encoding/json"
import "core:time"
import "core:crypto"
import "core:unicode/utf8"
import "core:net"
import "core:c/libc"
import "core:io"
import "core:bytes"
import "core:log"
import "core:runtime"

import "odin-http/client"


BASE_API_URL  : string : "https://api.twitch.tv/helix/"
FOLLOW_URL : string : BASE_API_URL + "channels/followers?first=1&broadcaster_id={0}"
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
    redirect_uri: string,
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
    scope: [dynamic]string,
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
    scope: [dynamic]string,
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
    scopes: [dynamic]string,
    user_id: string,
    expires_in: f64,
}

Autho_Token_Type :: enum {
    Client, User, Refresh,
}


get_autho_from_user :: proc (info: ^Info) -> (Success: bool) {
    ep := net.Endpoint{net.IP4_Loopback, 3000}
    sock, s_err := net.listen_tcp(ep)
    defer net.close(sock)
    if s_err != nil {
        fmt.println(s_err)
        return
    }
    log.debug("TCP Port Opened at", net.to_string(ep))

    r : [32]byte
    runes : [32]rune
    crypto.rand_bytes(r[:])
    chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for n in 0..<32 {
        runes[n] = rune(chars[int(r[n])%62])
    }
    state := utf8.runes_to_string(runes[:])
    defer delete_string(state)

    header := strings.builder_make()
    defer strings.builder_destroy(&header)
    fmt.sbprintf(&header, "client_id={0}&", info.creds.client_id)
    fmt.sbprint(&header, "redirect_uri=http://localhost:3000&")
    fmt.sbprint(&header, "response_type=code&")
    fmt.sbprint(&header, "scope=moderator%3Aread%3Afollowers&")
    fmt.sbprintf(&header, "state={0}", state)
    headers := strings.to_string(header)
    log.debug("Authorization Code Headers generated")

    // Alternatives for Linux & FreeBSD: firefox, x-www-browser
    command := ""
         when ODIN_OS == .Windows do command = "explorer" //rundll32 url.dll FileProtocolHandler "url" || from https://www.perlmonks.org/?node_id=9724
    else when ODIN_OS == .Linux   do command = "xdg-open"
    else when ODIN_OS == .FreeBSD do command = "xdg-open"
    else when ODIN_OS == .Darwin  do command = "open"
    else {
        log.panic("Unsuported OS")
        // log.fatal("Unsuported OS")
        // fmt.println("Unsuported OS")
        os.exit(-1)
    }

    log.debug("Opening Authorization Code URL")
    i := libc.system(strings.clone_to_cstring(fmt.tprintf("{0} \"{1}?{2}\"", command, USER_AUTHO_URL, headers)))
    if i == -1 {
        log.error("Unable to open Authorization Code URL")
        // fmt.println("Unable to open URL")
        os.exit(-1)
    }

    buf : [1024]u8
    con, epc, errc := net.accept_tcp(sock)
    log.debug("Accepting connection on", net.to_string(ep), "from", net.to_string(epc))

    if errc != nil {
        log.error(errc)
        // fmt.println(errc)
        return
    }
    if epc.address != ep.address {
        log.error("Dropping Connection from foreign address:", net.to_string(epc))
        // fmt.println("Dropping Connection from foreign address:", net.to_string(epc))
        return
    }
    read, read_err := net.recv_tcp(con, buf[:])
    if read_err != nil {
        log.error(read_err)
        // fmt.println(read_err)
        return
    }
    log.debug("Connection reseved on port", con)

    response_body := fmt.tprint("HeHe HoHo", time.now())
    sb := strings.builder_make()
    defer strings.builder_destroy(&sb)
    fmt.sbprint(&sb, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n")
    fmt.sbprintf(&sb, "Content-Length: %v\r\n", len(response_body))
    fmt.sbprint(&sb, "\r\n")
    fmt.sbprint(&sb, response_body)
    res := strings.to_string(sb)
    log.debug("Response Headers generated")

    res_written, res_err := net.send_tcp(con, transmute([]byte)res)
    if res_err != nil {
        log.error(res_err, res[:res_written])
        // fmt.println(res_err, res[:res_written])
        return
    }
    log.debug("Response sent to connection on", net.to_string(epc))


    raw_h := strings.split_lines(string(buf[:read]))[0]
    _,_,_, res_h := net.split_url(strings.split(raw_h, " ")[1])
    defer delete(res_h)

    if res_h["state"] != state {
        log.error("Possible CSRF.")
        log.warn("Got: {0}\nExpected: {1}\n", res_h["state"], state)
        //fmt.printf("Possible CSRF.\nGot: {0}\nExpected: {1}\n", res_h["state"], state)
        return
    }
    if "error" in res_h {
        log.error(res_h)
        //fmt.println(res_h)
        return
    }

    info.user_creds.code = strings.clone(res_h["code"])
    return true

}

get_token :: proc(info: ^Info, t_type: Autho_Token_Type) -> (Success: bool) {
    date := f64(time.now()._nsec)

    req: client.Request
    client.request_init(&req, .Post)
    defer client.request_destroy(&req)

    switch t_type{
    case .Client:
        if err := client.with_json(&req, info.creds); err != nil {
            log.error("JSON error:", err)
            //fmt.println("JSON error:", err)
            return
        }
    case .User:
        if !get_autho_from_user(info) do return
        req.headers["content-type"] = "application/x-www-form-urlencoded"
        bytes.buffer_write_string(&req.body, fmt.tprintf("client_id={0}&", info.user_creds.client_id))
        bytes.buffer_write_string(&req.body, fmt.tprintf("client_secret={0}&", info.user_creds.client_secret))
        bytes.buffer_write_string(&req.body, fmt.aprintf("grant_type={}&", info.user_creds.grant_type))
        bytes.buffer_write_string(&req.body, fmt.aprintf("code={}&", info.user_creds.code))
        bytes.buffer_write_string(&req.body, fmt.aprintf("redirect_uri={}", info.user_creds.redirect_uri))
    case .Refresh:
        re_creads := Refresh_Creds{
            client_id=info.creds.client_id, client_secret=info.creds.client_secret,
            grant_type = "refresh_token", refresh_token=info.user_token.refresh_token}
        if err := client.with_json(&req, re_creads); err != nil {
            log.error("JSON error:", err)
            //fmt.println("JSON error:", err)
            return
        }
    }
        
    res, err := client.request(CLIENT_TOKEN_URL, &req)
    if err != nil {
        log.error("Request failed:", err)
        //fmt.println("Request failed:", err)
        return
    }
    defer client.response_destroy(&res)
    if int(res.status) > 399 {
        log.error("Request failed:", res.status)
        //fmt.println("Request failed:", res.status)
        fmt.println(res.headers, client.response_body(&res), sep="\n")
        return
    }

    body, allocation, berr := client.response_body(&res)
    if berr != nil {
        log.error("Error retrieving response body:", berr)
        //fmt.println("Error retrieving response body:", berr)
        return
    }
    defer client.body_destroy(body, allocation)

    ares: union{Client_Autho_Res, User_Autho_Res}
    switch t_type {
    case .Client: ares = Client_Autho_Res{}
    case .Refresh, .User: ares = User_Autho_Res{}
    }

    switch v in body {
    case string:
        j_err: json.Unmarshal_Error
        switch _ in ares {
        case Client_Autho_Res:
            j_err = json.unmarshal_string(v, &ares.(Client_Autho_Res))
        case User_Autho_Res:
            j_err = json.unmarshal_string(v, &ares.(User_Autho_Res))
        }
        if j_err != nil {
            log.error("Unable to parse token body because of", j_err)
            //fmt.println("Unable to parse token body because of", j_err)
            return
        }
    case map[string]string:
        log.error("Invalid response body was reseived.")
        //fmt.println("Invalid response body was reseived.")
        return
    case client.Body_Error:
        log.error("Unable to parse token body because of", v)
        fmt.println("Unable to parse token body because of", v)
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

    out, j_err := json.marshal(info^, json.Marshal_Options{pretty = true})
    if j_err != nil {
        log.error("Unable to parse info because of", j_err)
        //fmt.println("Unable to parse info because of", j_err)
        fmt.println("Outputting new file contents")
        fmt.println(info)
        return
    }
    if !os.write_entire_file("info.json", out) {
        log.error("Unable to write to info.json.")
        //fmt.println("Unable to write to info.json.")
        fmt.println("Outputting new file contents")
        fmt.println(info)
        return
    }

    return true
}

validate_token :: proc(info: ^Info) -> (Success: bool) {
    date := f64(time.now()._nsec)

    req: client.Request
    client.request_init(&req)
    defer client.request_destroy(&req)
    req.headers["Authorization"] = fmt.aprint("OAuth", info.user_token.access_token)
        
    res, err := client.request(VALIDATE_URL, &req)
    body, _, _ := client.response_body(&res)
    if err != nil {
        log.error("Request Error:", err,"\n", body)
        //fmt.println("Request Error:", err,"\n", body)
        return
    }
    defer client.response_destroy(&res)
    if int(res.status) > 399 {
        log.error("Validation failed:", res.status,"\n", body)
        //fmt.println("Validation failed:", res.status,"\n", body)
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

get_id :: proc(user: string, req: ^client.Request, info: ^Info) -> (ID: int, Success: bool) {
    res, err := client.request(fmt.aprintf(USER_URL, user), req)
    if err != nil {
        log.warn("Unable to connect to twitch.")
        log.error(err)
        //fmt.println("Unable to connect to twitch.")
        //fmt.printf("Error: {0}", err)
        return
    }
    defer client.response_destroy(&res)

    for int(res.status) == 401 {
        log.warn("Token invalid. Attempting to Refresh/Reauthorize")
        // fmt.println("Token invalid. Attempting to Refresh/Reauthorize")
        if !get_token(info, .Refresh) {
            log.warn("Unable to Refresh. Trying to Reauthorize.")
            // fmt.println("Unable to Refresh. Trying to Reauthorize.")
            if !get_token(info, .User) {
                log.error("Unable to Reauthorize.")
                // fmt.println("Unable to Reauthorize.")
                return
            }
        }
        res, err = client.request(fmt.aprintf(USER_URL, user), req)
    }
    body, allocation, berr := client.response_body(&res)
    if berr != nil {
        log.error("Error retrieving response body:", berr)
        //fmt.println("Error retrieving response body:", berr)
        return
    }
    defer client.body_destroy(body, allocation)

    data := Get_Users_Res{}
    if p := json.unmarshal_string(body.(client.Body_Plain), &data); p != nil {
        log.error("Unable to parse id body because of", p)
        //fmt.println("Unable to parse id body because of", p)
        return
    }
    id, iderr := strconv.parse_int(data.data[0].id)
    if !iderr {
        log.error("Unable to parse id {0} as int\n", data.data[0].id)
        // fmt.printf("Unable to parse id {0} as int\n", data.data[0].id)
        return
    }

    return id, true
}

get_follows :: proc(id: int, req: ^client.Request, info: ^Info) -> (Count: int, Success: bool) {
    res, err := client.request(fmt.aprintf(FOLLOW_URL, id), req)
    if err != nil {
        log.warn("Unable to connect to twitch.")
        log.error(err)
        //fmt.println("Unable to connect to twitch.")
        //fmt.println("Error:", err)
        return
    }
    defer client.response_destroy(&res)

    for int(res.status) == 401 {
        log.warn("Token invalid. Attempting to Refresh/Reauthorize")
        // fmt.println("Token invalid. Attempting to Refresh/Reauthorize")
        if !get_token(info, .Refresh) {
            log.warn("Unable to Refresh. Trying to Reauthorize.")
            // fmt.println("Unable to Refresh. Trying to Reauthorize.")
            if !get_token(info, .User) {
                log.error("Unable to Reauthorize.")
                // fmt.println("Unable to Reauthorize.")
                return
            }
        }
        res, err = client.request(fmt.aprintf(FOLLOW_URL, id), req)
    }
    if int(res.status) == 400 {
        log.error("User ID", id, "is invalid")
        // fmt.printf("User ID {0} is invalid\n", id)
        return
    }

    body, allocation, berr := client.response_body(&res)
    if berr != nil {
        log.error("Error retrieving response body:", berr)
        // fmt.println("Error retrieving response body:", berr)
        return
    }
    defer client.body_destroy(body, allocation)

    data := Get_Users_Follows_Res{}
    if p := json.unmarshal_string(body.(client.Body_Plain), &data); p != nil {
        log.error("Unable to parse followers body because of", p)
        // fmt.println("Unable to parse followers body because of", p)
        return
    }
    
    return int(data.total), true
}

main :: proc() {
    //context.logger = log.create_console_logger()
    context.logger = log.create_console_logger(.Info)
    //context.logger = log.create_console_logger(.Warning)
    //context.logger = log.create_console_logger(.Error)
    //context.logger = log.create_console_logger(.Fatal)


    start_time := time.now()
    file, read_ok := os.read_entire_file_from_filename("./info.json")
    if !read_ok {
        log.error("Unable to read info.json")
        // fmt.println("Unable to read info.json")
        return
    }
    defer delete(file)

    info := Info{}
    if p := json.unmarshal(file, &info); p != nil {
        log.error("Unable to parse info.json because of", p)
        // fmt.println("Unable to parse info.json because of", p)
        return
    }
    if !validate_token(&info) {
        if !get_token(&info, .Refresh) {
        if !get_token(&info, .User) do return
    }}

    buf: [256]byte
    fmt.print("Username: ")

    to_read, err := os.read(os.stdin, buf[:])
    if err < 0 {
        fmt.println(cast(int)err)
        return
    }
    stm := string(buf[:to_read])
    // stm := "miss_court"
    for len(stm) > 24 {
        to_read, err = os.read(os.stdin, buf[:])
        if err < 0 {
            log.error(cast(int)err)
            // fmt.println(cast(int)err)
            return
        }
        stm = string(buf[:to_read])
    }
    stm = strings.clone(strings.trim_space(strings.trim_null(strings.trim(stm, "\r\n"))))
    goal: int = 0
    input_ok: bool = true

    for {
        fmt.print("Goal: ")
        user, err = os.read(os.stdin, buf[:])
        if err < 0 {
            log.error("Unable to read input becase of Error:", cast(int)err)
            // fmt.println("Unable to read input becase of Error:", cast(int)err)
            return
        }

        goal, input_ok = strconv.parse_int(strings.trim_space(string(buf[:user])))
        if input_ok do break

        fmt.println("Goal must be a whole number")
    }

    req: client.Request
    client.request_init(&req)
    defer client.request_destroy(&req)

    req.headers["accept"] = "application/vnd.twitchtv.v5+json"
    req.headers["Client-ID"] = info.creds.client_id
    req.headers["Authorization"] = fmt.aprint("Bearer", info.user_token.access_token)
    user_id, idok := get_id(stm, &req, &info)
    if !idok do return

    cur, old, fok := 0, 0, false
    errs := 0

    for {
        if time.since(start_time) >= (time.Hour - time.Minute){
            if !validate_token(&info) {
                if !get_token(&info, .Refresh) {
                if !get_token(&info, .User) do return
            }}
            start_time = time.now()
        }
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

    fmt.println("Press Enter to End...")
    pbuf:[1]byte
    os.read(os.stdin, pbuf[:])

}