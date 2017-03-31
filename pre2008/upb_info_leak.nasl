# OpenVAS Vulnerability Test
# $Id: upb_info_leak.nasl 3376 2016-05-24 07:53:16Z antu123 $
# Description: Ultimate PHP Board Information Leak
#
# Authors:
# Erik Stephens <erik@edgeos.com>
#
# Copyright:
# Copyright (C) 2004 Edgeos, Inc.
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

tag_summary = "The remote host is running Ultimate PHP Board (UPB).

There is a flaw in this version which may allow an attacker to view
private message board information.";

tag_solution = "Upgrade to the latest version (http://www.myupb.com)";

if(description)
{
  script_id(12198);
  script_version("$Revision: 3376 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-24 09:53:16 +0200 (Tue, 24 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-2276");
 script_bugtraq_id(6333);
  script_xref(name:"OSVDB", value:"4928");
  name = "Ultimate PHP Board Information Leak";
  script_name(name);
  summary = "Checks for UPB";
  script_summary(summary);
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("This script is Copyright (C) 2004 Edgeos, Inc.");
  family = "Web application abuses";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port) || !can_host_php(port:port))
  exit(0);

foreach d (make_list("/upb", "/board", cgi_dirs()))
{
  req = http_get(item:string(d, "/db/users.dat"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);
  if (egrep(pattern:"^Admin<~>", string:res))
  {
    security_message(port);
    exit(0);
  }
}
