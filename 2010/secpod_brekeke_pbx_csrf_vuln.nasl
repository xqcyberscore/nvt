##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_brekeke_pbx_csrf_vuln.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Brekeke PBX Cross-Site Request Forgery Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to change the
administrator's password by tricking a logged in administrator into visiting a
malicious web site.

Impact Level: Application.";

tag_affected = "Brekeke PBX version 2.4.4.8";

tag_insight = "The flaw exists in the application which fails to perform
validity checks on certain 'HTTP reqests', which allows an attacker to hijack
the authentication of users for requests that change passwords via the
pbxadmin.web.PbxUserEdit bean.";

tag_solution = "Upgrade to Brekeke PBX version 2.4.6.7 or later.
For updates refer to http://www.brekeke.com/";

tag_summary = "This host is running Brekeke PBX and is prone to Cross-Site
Request Forgery Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902066");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2114");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Brekeke PBX Cross-Site Request Forgery Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39952");
  script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/05/brekeke-pbx-2448-cross-site-request.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_require_ports("Services/www", 28080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_family("Web application abuses");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

pbxPort = get_http_port(default:28080);
if(!pbxPort){
  pbxPort = "28080";
}

if(!get_port_state(pbxPort)){
  exit(0);
}

## Send and receive response
sndReq = http_get(item:string("/pbx/gate?bean=pbxadmin.web.PbxLogin"),
                               port:pbxPort);
rcvRes = http_send_recv(port:pbxPort, data:sndReq);

## Confirm the application
if(">Brekeke PBX<" >< rcvRes)
{
  ## Grep for the version
  pbxVer = eregmatch(pattern:"Version ([0-9.]+)" , string:rcvRes);
  if(pbxVer[1] != NULL)
  {
    ## Check for Brekeke PBX version equal to 2.4.4.8
    if(version_is_equal(version:pbxVer[1], test_version:"2.4.4.8")){
      security_message(pbxPort);
    }
  }
}
