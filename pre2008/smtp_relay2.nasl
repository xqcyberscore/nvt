###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtp_relay2.nasl 13204 2019-01-21 17:32:45Z cfischer $
#
# Mail relaying (thorough test)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# starting from the relay test service (telnet relay-test.mail-abuse.org)
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
###############################################################################

# References
# Date: Mon, 25 Aug 2003 05:38:53 -0700
# From: "st0ff st0ff" <if0ff@YAHOO.COM>
# Subject: Can NT4 SMTP Service be misused for mail spamming
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#
# Date:	 Fri, 19 Sep 2003 16:47:45 +0200
# De:	eric@LIEGE.COM
# Subject:	Re: Can NT4 SMTP Service be misused for mail spamming
# To:	NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11852");
  script_version("$Revision: 13204 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 18:32:45 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0512");
  script_name("Mail relaying (thorough test)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl", "smtp_relay.nasl", "smtp_settings.nasl", "global_settings.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_exclude_keys("keys/is_private_addr", "keys/islocalhost");

  script_tag(name:"solution", value:"Upgrade your software or improve the configuration so that
  your SMTP server cannot be used as a relay any more.");

  script_tag(name:"summary", value:"The remote SMTP server appears to be insufficiently protected against mail relaying.");

  script_tag(name:"impact", value:"This means that spammers might be able to use your mail server to send their mails to the world.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");

# can't perform this test on localhost
if(islocalhost()) exit(0);
if(is_private_addr()) exit(0);

port = get_smtp_port(default:25);

# No use to try "advanced" tests if it is a wide open relay
if(get_kb_item("smtp/" + port + "/spam"))
  exit(0);

if(get_kb_item("smtp/" + port + "/qmail"))
  exit(0);

if(smtp_get_is_marked_wrapped(port:port))
  exit(0);

soc = smtp_open(port:port, data:NULL);
if(!soc)
  exit(0);

vtstrings = get_vt_strings();
domain = get_3rdparty_domain();
dest_name = get_host_name();
dest_ip = get_host_ip();
src_name = this_host_name();

t1 = strcat('nobody@', domain);
f1 = strcat(vtstrings["lowercase"], '@', dest_name);
f2 = strcat(vtstrings["lowercase"], '@[', dest_ip, ']');

i= 0;
from_l[i] = strcat("nobody@", domain);
to_l[i] = t1;
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@", rand_str(), ".", domain);
to_l[i] = t1;
i ++;
from_l[i] = vtstrings["lowercase"] + "@localhost";
to_l[i] = t1;
i ++;
from_l[i] = vtstrings["lowercase"];
to_l[i] = t1;
i ++;
from_l[i] = "";
to_l[i] = t1;
i ++;
from_l[i] = "";
to_l[i] = t1;
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@", dest_name);
to_l[i] = t1;
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@[", dest_ip, "]");
to_l[i] = t1;
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@", dest_name);
to_l[i] = strcat("nobody%", domain, "@", dest_name);
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@", dest_name);
to_l[i] = strcat("nobody%", domain, "@[", dest_ip, "]");
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@", dest_name);
to_l[i] = strcat('nobody@', domain, '@', dest_name);
i ++;
from_l[i] = strcat(vtstrings["lowercase"], "@", dest_name);
to_l[i] = strcat('"nobody@', domain, '"@[', dest_ip, ']');
i ++;
from_l[i] = f1;
to_l[i] = strcat('nobody@', domain, '@[', dest_ip, ']');
i ++;
from_l[i] = f2;
to_l[i] = strcat('@', dest_name, ':nobody@', domain);
i ++;
from_l[i] = f1;
to_l[i] = strcat('@[', dest_ip, ']:nobody@', domain);
i ++;
from_l[i] = f1;
to_l[i] = strcat(domain, '!nobody@[', dest_ip, ']');
i ++;
from_l[i] = strcat('postmaster@', dest_name);
to_l[i] = t1;
i ++;

rep = '';
send(socket:soc, data:strcat('HELO ', src_name, '\r\n'));
smtp_recv_line(socket:soc);
for (i = 0; soc && (from_l[i] || to_l[i]); i ++) {

  mf = strcat('MAIL FROM: <', from_l[i], '>\r\n');
  send(socket:soc, data:mf);
  l = smtp_recv_line(socket:soc);
  if(! l || l =~ '^5[0-9][0-9]') {
    smtp_close(socket:soc, check_data:l);
    soc = smtp_open(port:port, data:domain);
  } else {
    rt = strcat('RCPT TO: <', to_l[i], '>\r\n');
    send(socket:soc, data:rt);
    l = smtp_recv_line(socket:soc, code:"2[0-9]{2}");
    if(l) {
      mf -= '\r\n'; rt -= '\r\n';
      rep = strcat(rep, '\t', mf, '\n\t', rt, '\n\n');
      break;
    }

    smtp_close(socket:soc, check_data:l);
    soc = smtp_open(port:port, data:NULL);
  }
}

if (rep) {
  report = strcat("The remote SMTP server is insufficiently protected against relaying
This means that spammers might be able to use your mail server
to send their mails to the world.

The scanner was able to relay mails by sending those sequences:

", rep);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);