require ["fileinto", "mailbox"];
# Rspamd (milter_headers) adds "X-Spam: Yes" above the add-header score.
if header :is "X-Spam" "Yes" {
  fileinto :create "Junk";
}
