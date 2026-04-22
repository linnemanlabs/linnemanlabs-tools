# tetra pretty-printer v2
# usage: tetra getevents -o json | jq -rf pretty.jq

def basename: split("/") | last;

def short_fn:
  sub("^__x64_sys_"; "sys_") | sub("^__arm64_sys_"; "sys_");

# IPv4 literal or IPv6 with brackets, so [::1]:53 stays unambiguous
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

# read an integer-ish arg - Tetragon emits int_arg for int/long, size_arg for size_t
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

def sock_family:
  if   . == 1  then "AF_UNIX"
  elif . == 2  then "AF_INET"
  elif . == 10 then "AF_INET6"
  elif . == 16 then "AF_NETLINK"
  elif . == 17 then "AF_PACKET"
  else "family=\(.)" end;

# IANA protocol numbers - socket(2) proto arg. 0 = let kernel pick default for type.
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

select(.process_kprobe) |
.process_kprobe as $k |
($k.process.binary) as $bin |
($k.function_name | short_fn) as $fn |
$k.args as $a |
($k.return | intish) as $ret |

if   $fn == "udp_sendmsg" then
  "📨 udp-send  \($bin)  \($a[0].sock_arg | fmt_sock)  bytes=\($a[1] | intish // "?")"
elif $fn == "udp_recvmsg" then
  # prefer the kretprobe return value (actual bytes received)
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
  # skb dir = incoming: saddr/sport are the remote peer
  ($a[1].skb_arg) as $s |
  "📦 udp-pkt   \($bin)  \(addr_port($s.saddr; $s.sport)) -> \(addr_port($s.daddr; $s.dport))  len=\($s.len // "?")"
elif $fn == "sys_connect" then
  "🔌 sys-conn  \($bin)  fd=\($a[0].int_arg)  \($a[1].sockaddr_arg | fmt_sockaddr)"
elif $fn == "sys_accept" or $fn == "sys_accept4" then
  "🤝 accept    \($bin)  fd=\($a[0].int_arg)"
elif $fn == "sys_bind" then
  "📍 bind      \($bin)  fd=\($a[0].int_arg)  \($a[1].sockaddr_arg | fmt_sockaddr)"
elif $fn == "sys_socket" then
  "🧦 sys-sock  \($bin)  \($a[0].int_arg | sock_family)  \($a[1].int_arg | sock_type)  \($a[2].int_arg | sock_proto($a[1].int_arg))"
elif $fn == "security_bprm_creds_from_file" then
  "🧬 exec-sec  \($bin)  file=\($a[0].path_arg.path // $a[0].file_arg.path // "?")"
else
  "❓ \($fn) \($bin)  [\([$a[] | arg_summary] | join(", "))]"
end
