##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openfire_secbypass_900401.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Openfire 'AuthCheck' Filter Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

tag_impact = "Successful exploitation will cause execution of arbitrary code.
  Impact Level: Network";
tag_affected = "Ignite Realtime Openfire version prior to 3.6.1.";
tag_insight = "This vulnerability is due to error in the 'AuthCheck' filter while 
  imposing access restrictions via a specially crafted URL using 'setup/setup-'
  and followed by the directory traveral sequences. These can be exploited to
  cause underlying database, access or modify data.";
tag_solution = "Upgrade to 3.6.1
  http://www.igniterealtime.org/downloads/index.jsp";
tag_summary = "The host is running Openfire and is prone to security bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900401");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-6508");
  script_bugtraq_id(32189);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_name("Openfire 'AuthCheck Filter' Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32478/");
  script_xref(name : "URL" , value : "http://www.igniterealtime.org/downloads/index.jsp");
  script_xref(name : "URL" , value : "http://www.andreas-kurtz.de/advisories/AKADV2008-001-v1.0.txt");

  script_dependencies("http_version.nasl");
  script_require_ports(9090);

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");

port = 9090;

if(get_port_state(port))
{
  request = http_get(item:"/login.jsp", port:port);
  response = http_send_recv(port:port, data:request);
  if(response == NULL){
    exit(0);
  }
  if("Openfire Admin Console" >< response)
  {
    pattern = "Version: ([0-2]\..*|3\.[0-5](\..*)?|3\.6(\.0)?)($|[^.0-9])";
    if(egrep(pattern:pattern, string:response)){
      security_message(port);
    }
  }
}
