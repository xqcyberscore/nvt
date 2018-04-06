# OpenVAS Vulnerability Test
# $Id: iis_bdir.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Check for bdir.htr files
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
#
# Copyright:
# Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net
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

tag_summary = "The file bdir.htr is a default IIS files which can give
a malicious user a lot of unnecessary information about 
your file system.  Specifically, the bdir.htr script allows
the user to browse and create files on hard drive.  As this
includes critical system files, it is highly possible that
the attacker will be able to use this script to escalate
privileges and gain 'Administrator' access.

Example,
http://target/scripts/iisadmin/bdir.htr??c:";

tag_solution = "If you do not need these files, then delete them,
otherwise use suitable access control lists to ensure that
the files are not world-readable.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10577");
  script_version("$Revision: 9348 $");
  script_bugtraq_id(2280);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Check for bdir.htr files");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);   
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
if(get_port_state(port)) 
{
    if(is_cgi_installed_ka(item:"/scripts/iisadmin/bdir.htr", port:port))
    {
        security_message(port);
        exit(0);
    }
}

