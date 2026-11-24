# ============================================
# NetTools PRO - All In One - VERSI ? - ANTI FLOOD
# by Iwong - buat Eggdrop
# Perintah: ?ip ?whois ?port ?dns ?ping ?headers ?ssl ?scan
# puthelp = buat output banyak, anti flood
# putquick = buat output 1 baris, cepet
# ============================================
package require http

# ---------- 1. IP LOCATION - KOMPLIT ----------
bind pub - ?ip pub:net_ip
bind pub - ?iploc pub:net_ip
bind pub - ?ipinfo pub:net_ip

proc pub:net_ip {nick uhost handle chan text} {
    set target [lindex [split $text] 0]
    if {$target == ""} {
        puthelp "PRIVMSG $chan :Cara pake: ?ip <ip/domain> - Contoh: ?ip 8.8.8.8"
        return
    }
    regsub -all {^https?://} $target "" target
    regsub -all {^www\.} $target "" target
    set target [lindex [split $target "/"] 0]

    set url "http://ip-api.com/json/$target?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    if {[catch {set token [http::geturl $url -timeout 8000]}]} {
        puthelp "PRIVMSG $chan :API lagi down bro"
        return
    }
    set data [http::data $token]
    http::cleanup $token

    if {[string match "*\"status\":\"fail\"*" $data]} {
        puthelp "PRIVMSG $chan :$target -> IP / domain gak ketemu"
        return
    }
    proc net_get {data f} {
        if {[regexp "\"$f\":\"([^\"]*)\"" $data -> v]} { return $v }
        if {[regexp "\"$f\":(-?\[0-9.\]+)" $data -> v]} { return $v }
        if {[regexp "\"$f\":(true|false)" $data -> v]} { return $v }
        return "-"
    }
    set ip [net_get $data "query"]
    set cont [net_get $data "continent"]
    set country [net_get $data "country"]
    set code [net_get $data "countryCode"]
    set region [net_get $data "regionName"]
    set city [net_get $data "city"]
    set dist [net_get $data "district"]
    set zip [net_get $data "zip"]
    set lat [net_get $data "lat"]
    set lon [net_get $data "lon"]
    set tz [net_get $data "timezone"]
    set curr [net_get $data "currency"]
    set isp [net_get $data "isp"]
    set org [net_get $data "org"]
    set as [net_get $data "as"]
    set asname [net_get $data "asname"]
    set rev [net_get $data "reverse"]
    set mobile [net_get $data "mobile"]
    set proxy [net_get $data "proxy"]
    set hosting [net_get $data "hosting"]

    if {$mobile == "true"} { set mobile "Ya - HP / Seluler" } else { set mobile "Bukan - Kabel / Wifi" }
    if {$proxy == "true"} { set proxy "Ya - Pake VPN / Proxy" } else { set proxy "Tidak" }
    if {$hosting == "true"} { set hosting "Ya - Server / VPS / Hosting" } else { set hosting "Bukan - Rumahan / ISP" }

    puthelp "PRIVMSG $chan :\[IP INFO\] $ip - Reverse: $rev"
    puthelp "PRIVMSG $chan :Negara: $country ($code) - Benua: $cont - Provinsi: $region - Kota: $city ($dist) - Kode Pos: $zip"
    puthelp "PRIVMSG $chan :ISP: $isp | Org: $org"
    puthelp "PRIVMSG $chan :ASN: $as ($asname) | Mata Uang: $curr | Timezone: $tz"
    puthelp "PRIVMSG $chan :Mobile: $mobile | Proxy/VPN: $proxy | Hosting: $hosting"
    puthelp "PRIVMSG $chan :Koordinat: $lat, $lon - Maps: https://maps.google.com/?q=$lat,$lon"
}

# ---------- 2. WHOIS DOMAIN ----------
bind pub - ?whois pub:net_whois
bind pub - ?domain pub:net_whois
bind pub - ?cekdomain pub:net_whois

proc pub:net_whois {nick uhost handle chan text} {
    set domain [string tolower [lindex [split $text] 0]]
    if {$domain == ""} {
        puthelp "PRIVMSG $chan :Cara pake: ?whois <domain> - Contoh: ?whois forumcerdas.net"
        return
    }
    regsub -all {^https?://} $domain "" domain
    regsub -all {^www\.} $domain "" domain
    set domain [lindex [split $domain "/"] 0]
    puthelp "PRIVMSG $chan :Nge-whois $domain ... bentar $nick"
    if {[string match "*.id" $domain]} { set srv "whois.pandi.or.id"
    } elseif {[string match "*.com" $domain] || [string match "*.net" $domain]} { set srv "whois.verisign-grs.com"
    } elseif {[string match "*.org" $domain]} { set srv "whois.pir.org"
    } else { set srv "whois.verisign-grs.com" }
    if {[catch {set sock [socket $srv 43]}]} {
        puthelp "PRIVMSG $chan :Whois server down"
        return
    }
    fconfigure $sock -buffering line -blocking 0
    puts $sock "$domain"; flush $sock
    set ::wdata($sock) ""
    set ::wchan($sock) $chan
    set ::wdomain($sock) $domain
    fileevent $sock readable [list net_whois_read $sock]
    after 8000 [list net_whois_timeout $sock]
}
proc net_whois_read {sock} {
    if {[eof $sock]} { net_whois_finish $sock; return }
    catch {gets $sock line}
    if {$line != ""} { append ::wdata($sock) "$line\n" }
}
proc net_whois_finish {sock} {
    catch {close $sock}
    if {![info exists ::wdata($sock)]} { return }
    set chan $::wchan($sock); set domain $::wdomain($sock); set data $::wdata($sock)
    set out ""
    foreach line [split $data "\n"] {
        set l [string tolower $line]
        if {[string match "domain name:*" $l] || [string match "registrar:*" $l] || [string match "creation date:*" $l] || [string match "registry expiry date:*" $l] || [string match "expiry*" $l] || [string match "updated date:*" $l] || [string match "name server:*" $l] || [string match "status:*" $l]} {
            lappend out [regsub -all {\s+} $line " "]
        }
    }
    if {$out == ""} { puthelp "PRIVMSG $chan :$domain -> Gak ketemu / di-hide"
    } else {
        puthelp "PRIVMSG $chan :\[WHOIS\] $domain"
        set c 0
        foreach l $out { if {$c >= 7} { break }; puthelp "PRIVMSG $chan :$l"; incr c }
    }
    catch {unset ::wdata($sock) ::wchan($sock) ::wdomain($sock)}
}
proc net_whois_timeout {sock} {
    if {![info exists ::wdata($sock)]} { return }
    catch {close $sock}
    puthelp "PRIVMSG $::wchan($sock) :$::wdomain($sock) -> Timeout"
    catch {unset ::wdata($sock) ::wchan($sock) ::wdomain($sock)}
}

# ---------- 3. CEK PORT - 1 BARIS = putquick ----------
bind pub - ?port pub:net_port
bind pub - ?cekport pub:net_port
proc pub:net_port {nick uhost handle chan text} {
    set host [lindex [split $text] 0]
    set port [lindex [split $text] 1]
    if {$host == "" || $port == ""} {
        putquick "PRIVMSG $chan :Cara pake: ?port <host> <port> - Contoh: ?port irc.forumcerdas.net 6667"
        return
    }
    if {[catch {set sock [socket -async $host $port]}]} {
        putquick "PRIVMSG $chan :$host:$port -> CLOSED"
        return
    }
    fconfigure $sock -blocking 0 -buffering none
    fileevent $sock writable [list net_port_done $sock $chan $host $port]
    after 5000 [list net_port_timeout $sock $chan $host $port]
}
proc net_port_done {sock chan host port} {
    catch {close $sock}
    putquick "PRIVMSG $chan :$host:$port -> OPEN"
}
proc net_port_timeout {sock chan host port} {
    catch {close $sock}
    putquick "PRIVMSG $chan :$host:$port -> CLOSED / TIMEOUT"
}

# ---------- 4. DNS - 1 BARIS = putquick ----------
bind pub - ?dns pub:net_dns
proc pub:net_dns {nick uhost handle chan text} {
    set domain [lindex [split $text] 0]
    if {$domain == ""} {
        putquick "PRIVMSG $chan :Cara pake: ?dns <domain> - Contoh: ?dns google.com"
        return
    }
    if {[catch {set token [http::geturl "https://dns.google/resolve?name=$domain&type=A" -timeout 6000]}]} {
        putquick "PRIVMSG $chan :DNS API down"
        return
    }
    set data [http::data $token]; http::cleanup $token
    set ips ""
    foreach {a b} [regexp -all -inline {\"data\":\"(\[0-9.\]+)\"} $data] { lappend ips $b }
    if {$ips == ""} { putquick "PRIVMSG $chan :$domain -> DNS gak ketemu"
    } else { putquick "PRIVMSG $chan :\[DNS\] $domain -> IP: [join $ips ", "]" }
}

# ---------- 5. PING - 1 BARIS = putquick ----------
bind pub - ?ping pub:net_ping
proc pub:net_ping {nick uhost handle chan text} {
    set host [lindex [split $text] 0]
    if {$host == ""} {
        putquick "PRIVMSG $chan :Cara pake: ?ping <host>"
        return
    }
    if {[catch {set out [exec ping -c 1 -W 2 $host]}]} {
        putquick "PRIVMSG $chan :$host -> OFFLINE / TIMEOUT"
        return
    }
    if {[regexp {time=([0-9.]+)} $out -> ms]} {
        putquick "PRIVMSG $chan :$host -> ONLINE - Ping: ${ms}ms"
    } else {
        putquick "PRIVMSG $chan :$host -> ONLINE"
    }
}

# ---------- 6. HEADERS / SERVER WEB - VERSI PRO ----------
bind pub - ?headers pub:net_headers
bind pub - ?header pub:net_headers
bind pub - ?web pub:net_headers
bind pub - ?cekweb pub:net_headers

proc pub:net_headers {nick uhost handle chan text} {
    set host [lindex [split $text] 0]
    if {$host == ""} {
        puthelp "PRIVMSG $chan :Cara pake: ?headers <domain> - Contoh: ?headers google.com"
        return
    }
    regsub -all {^https?://} $host "" host
    regsub -all {^www\.} $host "" host
    set host [lindex [split $host "/"] 0]
    set url "http://$host"
    puthelp "PRIVMSG $chan :Lagi ngintip dapur $host ... bentar $nick"
    if {[catch {set token [http::geturl $url -timeout 7000 -method HEAD]}]} {
        if {[catch {set token [http::geturl "https://$host" -timeout 7000 -method HEAD]}]} {
            puthelp "PRIVMSG $chan :$host -> WEB DOWN / GAK BISA DIAKSES"
            return
        }
        set url "https://$host"
    }
    set code [http::code $token]
    set meta [http::meta $token]
    http::cleanup $token
    proc hget {meta key} {
        foreach {k v} $meta {
            if {[string tolower $k] == [string tolower $key]} { return $v }
        }
        return "-"
    }
    set server  [hget $meta "Server"]
    set powered [hget $meta "X-Powered-By"]
    set ctype   [hget $meta "Content-Type"]
    set cfray   [hget $meta "CF-Ray"]
    set cf_cache [hget $meta "CF-Cache-Status"]
    set location [hget $meta "Location"]
    if {$cfray != "-" || [string match -nocase "*cloudflare*" $server] || $cf_cache != "-"} {
        set cf "Ya - Dilindungi Cloudflare"
    } else {
        set cf "Tidak"
    }
    if {$server == "-"} { set server "Di-hide / Tidak ketahuan" }
    if {[string match "*200*" $code]} {
        set status "200 OK - Hidup"
    } elseif {[string match "*301*" $code] || [string match "*302*" $code]} {
        set status "$code - Redirect ke $location"
    } elseif {[string match "*403*" $code]} {
        set status "403 Forbidden - Di-block"
    } elseif {[string match "*404*" $code]} {
        set status "404 Not Found"
    } elseif {[string match "*500*" $code]} {
        set status "500 Error - Server error"
    } else {
        set status $code
    }
    puthelp "PRIVMSG $chan :\[WEB INFO\] $host - $url"
    puthelp "PRIVMSG $chan :Server: $server"
    puthelp "PRIVMSG $chan :Powered By: $powered - Type: $ctype"
    puthelp "PRIVMSG $chan :Cloudflare: $cf"
    puthelp "PRIVMSG $chan :Status: $status"
}

# ---------- 7. SSL CHECK - VERSI PRO + EXPIRED ----------
bind pub - ?ssl pub:net_ssl
bind pub - ?cekssl pub:net_ssl
proc pub:net_ssl {nick uhost handle chan text} {
    set host [lindex [split $text] 0]
    if {$host == ""} {
        puthelp "PRIVMSG $chan :Cara pake: ?ssl <domain> - Contoh: ?ssl google.com"
        return
    }
    regsub -all {^https?://} $host "" host
    regsub -all {^www\.} $host "" host
    set host [lindex [split $host "/"] 0]
    puthelp "PRIVMSG $chan :Lagi ngecek SSL $host ... bentar $nick"
    if {[catch {set out [exec sh -c "echo | openssl s_client -connect $host:443 -servername $host 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null"]} err]} {
        puthelp "PRIVMSG $chan :$host:443 -> NO SSL - Gak pake HTTPS / Port 443 ketutup"
        return
    }
    if {$out == ""} {
        puthelp "PRIVMSG $chan :$host:443 -> NO SSL - Gak pake HTTPS"
        return
    }
    set notBefore "-"; set notAfter "-"; set issuer "-"; set subject "-"
    foreach line [split $out "\n"] {
        if {[string match "notBefore*" $line]} { set notBefore [string range $line 10 end] }
        if {[string match "notAfter*" $line]} { set notAfter [string range $line 9 end] }
        if {[string match "issuer*" $line]} { set issuer [string range $line 7 end] }
        if {[string match "subject*" $line]} { set subject [string range $line 8 end] }
    }
    if {[regexp {CN *= *([^,/]+)} $issuer -> cn]} { set issuer $cn }
    puthelp "PRIVMSG $chan :\[SSL\] $host:443 -> SSL AKTIF - Pake HTTPS"
    puthelp "PRIVMSG $chan :Issuer: $issuer"
    puthelp "PRIVMSG $chan :Berlaku dari: $notBefore"
    puthelp "PRIVMSG $chan :Expired: $notAfter"
    puthelp "PRIVMSG $chan :Untuk: $subject"
}

# ---------- 8. SCAN PORT POPULER - ANTI FLOOD ----------
bind pub - ?scan pub:net_scan
proc pub:net_scan {nick uhost handle chan text} {
    set host [lindex [split $text] 0]
    if {$host == ""} {
        puthelp "PRIVMSG $chan :Cara pake: ?scan <host> - Contoh: ?scan irc.forumcerdas.net"
        return
    }
    puthelp "PRIVMSG $chan :Lagi nge-scan port populer di $host ... (22, 80, 443, 6667, 6697, 8080)"
    foreach p {22 80 443 6667 6697 8080} {
        pub:net_port $nick $uhost $handle $chan "$host $p"
    }
}

putlog "NetTools PRO ? ANTI FLOOD loaded - ?ip ?whois ?port ?dns ?ping ?headers ?ssl ?scan"