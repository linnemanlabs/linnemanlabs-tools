# tetra pretty-printer v2
# usage: tetra getevents -o json | jq -rf pretty.jq

def basename: split("/") | last;

def short_fn:
  sub("^__x64_sys_"; "sys_") | sub("^__arm64_sys_"; "sys_");

def addr_port($a; $p):
  (if ($a // "") | contains(":") then "[\($a)]" else ($a // "?") end)
  + ":" + (($p // "?") | tostring);

def fmt_sock:
  if . == null then "?"
  else addr_port(.saddr; .sport) + " -> " + addr_port(.daddr; .dport)
  end;

def fmt_sockaddr:
  if . == null then "?"
  else "\(.family // "?") " + addr_port(.addr; .port)
  end;

def intish:
  (.int_arg // .size_arg // .long_arg) // null;

def sock_type:
  . as $t
  | [
      (if   ($t % 16) == 1 then "STREAM"
       elif ($t % 16) == 2 then "DGRAM"
       elif ($t % 16) == 3 then "RAW"
       elif ($t % 16) == 5 then "SEQPACKET"
       else "type=\($t)" end),
      (if ($t / 2048    | floor) % 2 == 1 then "NONBLOCK" else empty end),
      (if ($t / 524288  | floor) % 2 == 1 then "CLOEXEC"  else empty end)
    ] | join("|");

def sockopt_level:
  if   . == 0   then "SOL_IP"
  elif . == 1   then "SOL_SOCKET"
  elif . == 6   then "SOL_TCP"
  elif . == 17  then "SOL_UDP"
  elif . == 41  then "SOL_IPV6"
  elif . == 263 then "SOL_PACKET"
  else "level=\(.)" end;

def sockopt_name($level):
  . as $n |
  if $level == 1 then          # SOL_SOCKET
    if   $n == 25 then "SO_BINDTODEVICE"
    elif $n == 26 then "SO_ATTACH_FILTER"
    elif $n == 32 then "SO_SNDBUFFORCE"
    elif $n == 33 then "SO_RCVBUFFORCE"
    elif $n == 36 then "SO_MARK"
    elif $n == 50 then "SO_ATTACH_BPF"
    elif $n == 51 then "SO_ATTACH_REUSEPORT_CBPF"
    elif $n == 52 then "SO_ATTACH_REUSEPORT_EBPF"
    else "opt=\($n)" end
  elif $level == 0 then        # SOL_IP
    if   $n == 3  then "IP_HDRINCL"
    elif $n == 15 then "IP_FREEBIND"
    elif $n == 19 then "IP_TRANSPARENT"
    elif $n == 22 then "IP_NODEFRAG"
    else "opt=\($n)" end
  elif $level == 6 then        # SOL_TCP
    if   $n == 19 then "TCP_REPAIR"
    elif $n == 31 then "TCP_ULP"
    else "opt=\($n)" end
  elif $level == 41 then       # SOL_IPV6
    if   $n == 36 then "IPV6_HDRINCL"
    elif $n == 75 then "IPV6_TRANSPARENT"
    elif $n == 78 then "IPV6_FREEBIND"
    else "opt=\($n)" end
  elif $level == 263 then      # SOL_PACKET
    if   $n == 1  then "PACKET_ADD_MEMBERSHIP"
    elif $n == 5  then "PACKET_RX_RING"
    elif $n == 13 then "PACKET_TX_RING"
    elif $n == 18 then "PACKET_FANOUT"
    elif $n == 20 then "PACKET_QDISC_BYPASS"
    else "opt=\($n)" end
  else "opt=\($n)" end;

def sock_family:
  if   . == 1  then "AF_UNIX"
  elif . == 2  then "AF_INET"
  elif . == 10 then "AF_INET6"
  elif . == 16 then "AF_NETLINK"
  elif . == 17 then "AF_PACKET"
  else "family=\(.)" end;

def sock_proto($type):
  if   . == 0   then (if $type == 1 then "TCP" elif $type == 2 then "UDP" else "default" end)
  elif . == 1   then "ICMP"
  elif . == 2   then "IGMP"
  elif . == 6   then "TCP"
  elif . == 17  then "UDP"
  elif . == 41  then "IPV6"
  elif . == 47  then "GRE"
  elif . == 50  then "ESP"
  elif . == 51  then "AH"
  elif . == 58  then "ICMPV6"
  elif . == 89  then "OSPF"
  elif . == 112 then "VRRP"
  elif . == 132 then "SCTP"
  elif . == 136 then "UDPLITE"
  else "proto=\(.)" end;

def decode_sun_path:
  if . == null or . == "" then "<unnamed>"
  else
    (@base64d | .[2:]) as $raw |
    if   ($raw | length) == 0          then "<unnamed>"
    elif ($raw | startswith("\u0000")) then "@\($raw[1:])"
    else ($raw | rtrimstr("\u0000"))
    end
  end;

def arg_summary:
  . as $a
  | if   $a.int_arg      != null then "int=\($a.int_arg)"
    elif $a.size_arg     != null then "size=\($a.size_arg)"
    elif $a.long_arg     != null then "long=\($a.long_arg)"
    elif $a.string_arg   != null then "str=\"\($a.string_arg)\""
    elif $a.sock_arg     != null then ($a.sock_arg | fmt_sock)
    elif $a.sockaddr_arg != null then ($a.sockaddr_arg | fmt_sockaddr)
    elif $a.path_arg     != null then "path=\($a.path_arg.path // $a.path_arg)"
    elif $a.bytes_arg    != null then "bytes=<\($a.bytes_arg | length)b>"
    elif $a.skb_arg      != null then "skb[\(addr_port($a.skb_arg.saddr; $a.skb_arg.sport)) -> \(addr_port($a.skb_arg.daddr; $a.skb_arg.dport))]"
    else ($a | keys_unsorted[0] // "empty") end;

# Curated set of "this process has real power" caps
# Priority order matters - first match wins, CAP_SYS_ADMIN is god mode.
def danger_caps:
  ["CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_PTRACE",
   "CAP_BPF", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_DAC_OVERRIDE",
   "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_BOOT",
   "CAP_SYS_CHROOT", "CAP_MAC_ADMIN"];

# Pick the first danger cap in process.cap.effective. Effective set is what's
# active right now - permitted-but-not-effective caps are available, not in use.
def pick_danger_cap($proc):
  ($proc.cap.effective // []) as $eff
  | [danger_caps[] | select(. as $c | $eff | index($c))][0] // "";

def cap_trailer($proc):
  pick_danger_cap($proc) as $c
  | if $c == "" then "" else "🛑 \($c)" end;

# right-align caps at column 120 (Tetragon compact encoder convention)
def with_caps($proc):
  . as $line
  | cap_trailer($proc) as $caps
  | if $caps == "" then $line
    else
      ($line | length) as $len
      | (if $len < 120 then 120 - $len else 1 end) as $pad
      | $line + (" " * $pad) + $caps
    end;

# Prepend an ALERT line when any tag starts with "alert."
# Pulls the alert name from the first matching tag and the human-readable
# context from the message field.
# Both are optional, falls through cleanly if either is missing.
def with_alert($k):
  . as $line |
  ($k.tags // []) as $tags |
  ($k.message // "") as $msg |
  ($tags | map(select(startswith("alert."))) | first // "") as $alert |
  if $alert == "" then $line
  else
    ($alert | sub("^alert\\."; "")) as $name |
    "🚨 ALERT     \($name)\(if $msg != "" then "  \($msg)" else "" end)\n\($line)"
  end;

# event dispatch

if .process_exec then
  .process_exec as $e |
  ($e.parent.binary // "?" | split("/") | last) as $pname |
  "🚀 exec      \($pname) -> \($e.process.binary) \($e.process.arguments // "")"
  | with_caps($e.process)

elif .process_exit then
  .process_exit as $e |
  ($e.status // 0) as $status |
  ($e.signal // "") as $sig |
  "💥 exit      \($e.process.binary)  \($status)\(if $sig != "" then " sig=\($sig)" else "" end)"
  | with_caps($e.process)

elif .process_kprobe then
  .process_kprobe as $k |
  ($k.process.binary) as $bin |
  ($k.function_name | short_fn) as $fn |
  ($k.args // [])as $a |
  ($k.return | intish) as $ret |

  (if  $fn == "udp_sendmsg" then
    "📨 udp-send  \($bin)  \($a[0].sock_arg | fmt_sock)  bytes=\($a[1] | intish // "?")"
  elif $fn == "udp_recvmsg" then
    (if   $ret != null and $ret >= 0 then "bytes=\($ret)"
     elif $ret != null               then "err=\($ret)"
     else "len=\($a[1] | intish // "?")" end) as $size |
    "📬 udp-recv  \($bin)  \($a[0].sock_arg | fmt_sock)  \($size)"
  elif $fn == "udp_connect" then
    "🧷 udp-conn  \($bin)  sport=\($a[0].sock_arg.sport // "?")"
  elif $fn == "tcp_sendmsg" then
    "📤 tcp-send  \($bin)  \($a[0].sock_arg | fmt_sock)  bytes=\($a[1] | intish // "?")"
  elif $fn == "tcp_recvmsg" then
    (if   $ret != null and $ret >= 0 then "bytes=\($ret)"
     elif $ret != null               then "err=\($ret)"
     else "len=\($a[1] | intish // "?")" end) as $size |
    "📥 tcp-recv  \($bin)  \($a[0].sock_arg | fmt_sock)  \($size)"
  elif $fn == "tcp_connect" then
    "🔗 tcp-conn  \($bin)  \($a[0].sock_arg | fmt_sock)"
  elif $fn == "tcp_close" then
    "🧹 tcp-close \($bin)  \($a[0].sock_arg | fmt_sock)"
  elif $fn == "skb_consume_udp" then
    ($a[1].skb_arg) as $s |
    "📦 udp-pkt   \($bin)  \(addr_port($s.saddr; $s.sport)) -> \(addr_port($s.daddr; $s.dport))  len=\($s.len // "?")"
  elif $fn == "raw_sendmsg" then
    ($a[0].sock_arg) as $s |
    ($s.sport // 0 | sock_proto(0)) as $proto |
    "🪤 raw-send  \($bin)  AF_INET proto=\($proto)  bytes=\($a[1] | intish // "?")\(if $ret != null and $ret < 0 then "  err=\($ret)" else "" end)"
  elif $fn == "packet_sendmsg" then
    # AF_PACKET: link-layer injection. saddr/daddr are "<nil>" because
    # AF_PACKET operates below IP - no IP addresses exist at this layer
    ($a[0].sock_arg) as $s |
    "🧪 pkt-send  \($bin)  AF_PACKET \($s.type // "?")  bytes=\($a[1] | intish // "?")\(if $ret != null and $ret < 0 then "  err=\($ret)" else "" end)"
  elif $fn == "__dev_queue_xmit" then
    # Universal L2 egress - every packet leaving via any interface passes here
    # skb has parsed fields the sock-level hooks didn't see
    ($a[0].skb_arg) as $s |
    (($s.protocol // "") | sub("^IPPROTO_"; "") | ascii_downcase) as $proto |
    ($proto | if . == "" then "" else " \(.)" end) as $proto_str |
    "🚚 dev-qxmit \($bin)  \(addr_port($s.saddr; $s.sport)) -> \(addr_port($s.daddr; $s.dport))\($proto_str)  len=\($s.len // "?")"
  elif $fn == "__dev_direct_xmit" then
    # Universal L2 egress - every packet leaving via any interface passes here
    # skb has parsed fields the sock-level hooks didn't see
    ($a[0].skb_arg) as $s |
    (($s.protocol // "") | sub("^IPPROTO_"; "") | ascii_downcase) as $proto |
    ($proto | if . == "" then "" else " \(.)" end) as $proto_str |
    "🛻 dev-xmit  \($bin)  \(addr_port($s.saddr; $s.sport)) -> \(addr_port($s.daddr; $s.dport))\($proto_str)  len=\($s.len // "?")"
  elif $fn == "ip_local_out" then
    # IPv4-specific egress - fires only for IP-layer packets, not AF_PACKET.
    # good for distinguishing "went through the IP stack" from "injected raw"
    ($a[2].skb_arg) as $s |
    (($s.protocol // "") | sub("^IPPROTO_"; "") | ascii_downcase) as $proto |
    ($proto | if . == "" then "" else " \(.)" end) as $proto_str |
    "📮 ip-xmit   \($bin)  \(addr_port($s.saddr; $s.sport)) -> \(addr_port($s.daddr; $s.dport))\($proto_str)  len=\($s.len // "?")"
  elif $fn == "sys_connect" then
    "🔌 sys-conn  \($bin)  fd=\($a[0].int_arg)  \($a[1].sockaddr_arg | fmt_sockaddr)"
  elif $fn == "sys_accept" or $fn == "sys_accept4" then
    "🤝 accept    \($bin)  fd=\($a[0].int_arg)"
  elif $fn == "sys_bind" then
    "📍 bind      \($bin)  fd=\($a[0].int_arg)  \($a[1].sockaddr_arg | fmt_sockaddr)"
  elif $fn == "sys_socket" then
    "🧦 sys-sock  \($bin)  \($a[0].int_arg | sock_family)  \($a[1].int_arg | sock_type)  \($a[2].int_arg | sock_proto($a[1].int_arg))"
  elif $fn == "sys_setsockopt" then
    ($a[0].int_arg) as $fd |
    ($a[1].int_arg) as $level |
    ($a[2].int_arg) as $optname |
    "🪛 sock-opt  \($bin)  fd=\($fd)  \($level | sockopt_level)/\($optname | sockopt_name($level))"
  elif $fn == "security_bprm_creds_from_file" then
    "🧬 exec-sec  \($bin)  file=\($a[0].path_arg.path // $a[0].file_arg.path // "?")"
  elif $fn == "security_file_permission" then
    # LSM hook on actual read/write operations (not just open)
    # mask bits: MAY_EXEC=1, MAY_WRITE=2, MAY_READ=4, MAY_APPEND=8
    # Return 0 = allowed, -EACCES etc = denied
    ($a[0].file_arg.path // "?") as $path |
    ($a[1].int_arg // 0) as $mask |
    (if   ($mask / 4 | floor) % 2 == 1 then "read"
     elif ($mask / 2 | floor) % 2 == 1 then "write"
     elif ($mask / 1 | floor) % 2 == 1 then "exec"
     else "?" end) as $mode |
    (if   $mode == "read"  then "📖 fs-read  "
     elif $mode == "write" then "📝 fs-write "
     elif $mode == "exec"  then "🔧 fs-exec  "
     else "🔒 file-perm " end) as $icon |
    "\($icon) \($bin)  \($path)\(if $ret != null and $ret != 0 then "  err=\($ret)" else "" end)"
  elif $fn == "security_socket_connect" then
    # LSM hook: fires before the kernel hands a connect() to the protocol layer.
    # Sees every family (UNIX, INET, INET6, NETLINK, PACKET, ...). Policy splits
    # extraction by family: bytes_arg for AF_UNIX (sun_path), sockaddr_arg for
    # AF_INET/INET6.
    ($a[0].sock_arg) as $s |
    ($s.family // "?") as $fam |
    ($s.type // "" | sub("^SOCK_"; "")) as $stype |
    ($s.protocol // "" | sub("^IPPROTO_"; "")) as $proto |
    (if $fam == "AF_UNIX" then
       ($a[1].bytes_arg | decode_sun_path) as $path |
       "🛂 sec-conn  \($bin)  unix/\($stype) -> \($path)"
     elif $fam == "AF_INET" or $fam == "AF_INET6" then
       ($a[1].sockaddr_arg) as $sa |
       ($fam | sub("^AF_"; "") | ascii_downcase) as $famshort |
       "🛂 sec-conn  \($bin)  \($famshort)/\($stype) \($proto) -> \(addr_port($sa.addr; $sa.port))"
     else
       "🛂 sec-conn  \($bin)  \($fam)  [\([$a[] | arg_summary] | join(", "))]"
     end)
  else
    "❓ \($fn) \($bin)  [\([$a[] | arg_summary] | join(", "))]"
  end)
  | with_caps($k.process)
  | with_alert($k)

else empty
end
