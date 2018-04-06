# OpenVAS Vulnerability Test
# $Id: eftp_root_disclosure.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: EFTP installation directory disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "The remote FTP server can be used to determine the
installation directory by sending a request on an
unexisting file.

An attacker may use this flaw to gain more knowledge about
this host, such as its filesystem layout.";

tag_solution = "update your FTP server";

# References:
# Date:  Wed, 12 Sep 2001 04:36:22 -0700 (PDT)
# From: "ByteRage" <byterage@yahoo.com>
# Subject: EFTP Version 2.0.7.337 vulnerabilities
# To: bugtraq@securityfocus.com

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11093");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3331, 3333);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1109");
 name = "EFTP installation directory disclosure ";
 
 script_name(name);
 





 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "FTP";

 script_family(family);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("ftp_func.inc");

cmd[0] = "GET";
cmd[1] = "MDTM";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if (!login) login = "ftp";
if (!pass) pass = "openvas@example.com";

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

if( ftp_authenticate(socket:soc, user:login, pass:pass))
{
  for (i = 0; i < 2; i=i+1)
  {
    req = string(cmd[i], " openvas", rand(), "\r\n");
    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);
    if (egrep(string:r, pattern:" '[C-Z]:\\'"))
    {
      security_message(port);
      ftp_close(socket:soc);
      exit(0);
    }
  }
}
