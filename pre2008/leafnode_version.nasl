# OpenVAS Vulnerability Test
# $Id: leafnode_version.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Leafnode denials of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
#

tag_summary = "According to its version number that OpenVAS read in the banner, 
your Leafnode NNTP server is vulnerable to a denial of service.

** Note that OpenVAS did not check the actual flaw and
** relied upon the banner, so this may be a false positive.";

tag_solution = "upgrade it to 1.9.48 or later";

if(description)
{
 script_id(11517);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-1661");
 script_bugtraq_id(6490);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 name = "Leafnode denials of service";
 script_name(name);

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "General";
 script_family(family);

 script_dependencies("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

port = get_kb_item("Services/nntp");
if (! port) port = 119;
if (! get_port_state(port)) exit(0);

k = string("nntp/banner/", port);
b = get_kb_item(k);
if (! b)
{
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  b = recv_line(socket: soc, length: 2048);
  close(soc);
}

# Example of banner:
# 200 Leafnode NNTP Daemon, version 1.9.32.rel running at localhost (my fqdn: www.openvas.org)

if ("Leafnode" >< b)
{
  if (ereg(string: b, pattern: "version +1\.9\.2[0-9]"))
  {
    report = "
According to its version number that OpenVAS read in the banner, 
your Leafnode NNTP server is vulnerable to a denial of service:
it may go into an infinite loop with 100% CPU use when an article 
that has been crossposted to several groups, one of which is the 
prefix of another, and when this article is then requested by its 
Message-ID.

** Note that OpenVAS did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Solution: upgrade it to 1.9.48 or later";
    security_message(port: port, data: report);
  }
  else if (ereg(string: b, pattern: "version +1\.9\.([3-9]|[1-3][0-9]|4[0-7])[^0-9]"))
  {
    report="
According to its version number that OpenVAS read in the banner, 
your Leafnode NNTP server is vulnerable to a denial of service:
it may hangs without consuming CPU while waiting for data that 
never come.

** Note that OpenVAS did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Solution: upgrade it to 1.9.48 or later";
     security_message(port: port, data: report);
  }

  # Better double check this old version, although this is not strictly
  # a _security_ bug
  if (ereg(string: b, pattern: "version +1\.9\.19"))
  {
    report="
According to its version number (1.9.19) that OpenVAS read in 
the banner, your Leafnode NNTP server has some critical 
bugs and should not be used: it can corrupt parts of its news
spool under certain circumstances.

** Note that OpenVAS did not check the actual flaw and
** relied upon the banner, so this may be a false positive.

Solution: upgrade it to 1.9.48 or later";
     security_message(port: port, data: report);
  }
}
