# Milter endpoint for Postfix. self_scan: the proxy worker scans mail itself,
# so the separate normal worker (disabled below) is not needed.
milter = yes;
timeout = 120s;
bind_socket = "*:11332";
upstream "local" {
  default = yes;
  self_scan = yes;
}
count = 1;
